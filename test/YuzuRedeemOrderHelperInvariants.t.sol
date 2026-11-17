// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {Order, OrderStatus} from "../src/interfaces/proto/IYuzuOrderBookDefinitions.sol";
import {YuzuILPV3} from "../src/YuzuILPV3.sol";
import {YuzuRedeemOrderHelper} from "../src/helpers/YuzuRedeemOrderHelper.sol";
import {FEE_MANAGER_ROLE, ORDER_FILLER_ROLE, PAUSE_MANAGER_ROLE} from "./helpers/TestRoles.sol";
import {YuzuV3TestBase, YuzuV3USDT0Mock} from "./helpers/YuzuV3TestBase.sol";

/// @dev Handler exposing user / filler / admin / third-party-donor actions plus time warps and
/// fee mutations, over a single deployed `YuzuRedeemOrderHelper` bound to ILP V3. No assertions
/// live here -- only ghost bookkeeping the outer `invariantTest_*` functions compare against live
/// contract reads, matching the repo's existing handler idiom (`StakedYuzuUSDHandler`,
/// `test/StakedYuzuUSD.t.sol`).
///
/// Every `vm.prank` below is issued after all argument values that need an external call (e.g.
/// `helper.MAX_FEE_BPS()`) have been read into locals: an external call evaluated as an argument
/// would otherwise consume the prank.
contract YuzuRedeemOrderHelperInvariantHandler is CommonBase, StdCheats, StdUtils {
    uint256 internal constant NUM_ACTORS = 3;
    uint256 internal constant INITIAL_DEPOSIT = 1_000e6;
    uint256 internal constant TOP_UP_DEPOSIT = 200e6;

    YuzuILPV3 internal immutable vault;
    YuzuRedeemOrderHelper internal immutable helper;
    YuzuV3USDT0Mock internal immutable asset;

    address internal immutable admin;
    address internal immutable feeManager;
    address internal immutable vaultFiller; // legacy-EOA analogue: ORDER_FILLER_ROLE directly on the vault
    address internal immutable outsider; // never granted FILLER_ROLE anywhere
    address internal immutable helperFiller; // holds FILLER_ROLE on the helper

    address[NUM_ACTORS] internal actors;

    uint256[] public helperOrderIds;
    uint256[] public directOrderIds; // created straight on the vault, bypassing the helper

    mapping(uint256 => address) internal _expectedOwner;

    // --- ghost accounting, read by the outer invariant functions --------------------------------

    uint256 public totalDonated; // I1
    uint256 public assetsSettledAccordingToVault; // I9
    uint256 public actualAssetsDeliveredToReceivers; // I9

    bool public unauthorizedAssetMoveObserved; // I4
    bool public illegalCancelObserved; // I8
    bool public earlyFeeSettleObserved; // I2d
    uint256 public unexpectedFinalizeFailures; // I6
    uint256 public unexpectedUserCancelFailures; // I6
    bool public gatedOwnerServedObserved; // I10
    uint256 public unexpectedSettleFeeFailures; // I2c

    // --- reachability counters (diagnostics, never asserted) -------------------------------------

    uint256 public createdViaHelperCount;
    uint256 public createdWithFeeCount;
    uint256 public helperFillCount;
    uint256 public vaultFillCount;
    uint256 public finalizedViaHelperCount;
    uint256 public finalizedAtVaultCount;
    uint256 public userCancelCount;
    uint256 public whitelistBlockedCount;
    uint256 public adminCancelCount;
    uint256 public settleFeeCount;

    constructor(
        YuzuILPV3 vault_,
        YuzuRedeemOrderHelper helper_,
        YuzuV3USDT0Mock asset_,
        address admin_,
        address feeManager_,
        address vaultFiller_,
        address outsider_
    ) {
        vault = vault_;
        helper = helper_;
        asset = asset_;
        admin = admin_;
        feeManager = feeManager_;
        vaultFiller = vaultFiller_;
        outsider = outsider_;

        helperFiller = makeAddr("invariantHelperFiller");
        bytes32 fillerRole = helper_.FILLER_ROLE();
        vm.prank(admin_);
        helper_.grantRole(fillerRole, helperFiller);
        vm.prank(helperFiller);
        asset_.approve(address(helper_), type(uint256).max);

        address[] memory partners = new address[](NUM_ACTORS);
        for (uint256 i = 0; i < NUM_ACTORS; i++) {
            address a = makeAddr(string.concat("invariantActor", vm.toString(i)));
            actors[i] = a;
            partners[i] = a;

            asset_.mint(a, 1_000_000e6);
            vm.prank(a);
            asset_.approve(address(vault_), type(uint256).max);
            vm.prank(a);
            vault_.approve(address(helper_), type(uint256).max);
            vm.prank(a);
            vault_.deposit(INITIAL_DEPOSIT, a);
        }

        // The helper starts as deployed (whitelist on); every actor starts listed, and the
        // `setWhitelisted` / `setWhitelistEnabled` actions churn both from there.
        bytes32 listRole = helper_.WHITELIST_MANAGER_ROLE();
        vm.startPrank(admin_);
        helper_.grantRole(listRole, admin_);
        helper_.setWhitelisted(partners, true);
        vm.stopPrank();

        asset_.mint(outsider_, 1_000_000e6);
        vm.prank(outsider_);
        asset_.approve(address(helper_), type(uint256).max);
    }

    // --- internal helpers -------------------------------------------------------------------------

    function _actor(uint256 seed) internal view returns (address) {
        return actors[_bound(seed, 0, NUM_ACTORS - 1)];
    }

    /// @dev True when the helper must refuse `owner` right now: list on and owner not on it.
    function _gated(address owner) internal view returns (bool) {
        return helper.whitelistEnabled() && !helper.isWhitelisted(owner);
    }

    // --- views for the outer invariant contract --------------------------------------------------

    function helperOrderCount() external view returns (uint256) {
        return helperOrderIds.length;
    }

    function expectedOwnerOf(uint256 orderId) external view returns (address) {
        return _expectedOwner[orderId];
    }

    // --- actions ------------------------------------------------------------------------------------

    /// @dev A user deposits fresh assets so later actions always have shares to work with.
    function topUpDeposit(uint256 actorSeed, uint256 amountSeed) external {
        address a = _actor(actorSeed);
        uint256 amount = _bound(amountSeed, 1e6, TOP_UP_DEPOSIT);
        vm.prank(a);
        vault.deposit(amount, a);
    }

    /// @dev A user creates a redeem order THROUGH the helper, as the order owner. The helper pulls
    /// its fee (if any) in shares out of `tokens` and escrows it. I5's expectation is recorded here,
    /// before any fee mutation or fill can touch this order.
    function createOrderViaHelper(uint256 actorSeed, uint256 tokensSeed) external {
        address a = _actor(actorSeed);
        uint256 shareBal = vault.balanceOf(a);
        if (shareBal == 0) return;
        uint256 tokens = _bound(tokensSeed, 1, shareBal);
        uint256 maxHelperFeeBps = helper.MAX_FEE_BPS();

        bool gated = _gated(a);

        vm.prank(a);
        try helper.createRedeemOrderWithMaxFee(tokens, a, 1_000_000, maxHelperFeeBps, 1) returns (uint256 orderId) {
            if (gated) gatedOwnerServedObserved = true;
            _expectedOwner[orderId] = a;
            helperOrderIds.push(orderId);
            createdViaHelperCount++;
            if (helper.orderFeeTokens(orderId) != 0) createdWithFeeCount++;
        } catch {
            if (gated) whitelistBlockedCount++;
        }
    }

    /// @dev A user creates a redeem order DIRECTLY on the vault, bypassing the helper entirely --
    /// `controller == a`, never the helper. This is the pool I8's fuzz draws "foreign" orders from.
    function createOrderDirectlyOnVault(uint256 actorSeed, uint256 tokensSeed) external {
        address a = _actor(actorSeed);
        uint256 shareBal = vault.balanceOf(a);
        if (shareBal == 0) return;
        uint256 tokens = _bound(tokensSeed, 1, shareBal);

        vm.prank(a);
        try vault.createRedeemOrder(tokens, a, a) returns (uint256 orderId) {
            directOrderIds.push(orderId);
        } catch {}
    }

    /// @dev `helperFiller` fills+finalizes a pending helper-created order in one call, settling the
    /// escrowed fee inline. Tracks I9's two independently-derived totals: what the vault recorded as
    /// settled, and what the receiver's balance actually moved by.
    function fillAndFinalizeViaHelper(uint256 orderIndexSeed) external {
        if (helperOrderIds.length == 0) return;
        uint256 orderId = helperOrderIds[_bound(orderIndexSeed, 0, helperOrderIds.length - 1)];
        Order memory order = vault.getRedeemOrder(orderId);
        if (order.status != OrderStatus.Pending) return;

        uint256 maxAssets = type(uint128).max;
        asset.mint(helperFiller, maxAssets);
        uint256 receiverBalBefore = asset.balanceOf(order.receiver);
        bool gated = _gated(order.owner);

        vm.prank(helperFiller);
        try helper.fillAndFinalizeRedeemOrder(orderId, maxAssets, block.timestamp + 1 days) {
            if (gated) gatedOwnerServedObserved = true;
            assetsSettledAccordingToVault += vault.getRedeemOrder(orderId).assets;
            actualAssetsDeliveredToReceivers += asset.balanceOf(order.receiver) - receiverBalBefore;
            helperFillCount++;
        } catch {
            if (gated) whitelistBlockedCount++;
        }
    }

    /// @dev `outsider` never holds `FILLER_ROLE` anywhere. I4: this must never move an asset.
    function attemptUnauthorizedFill(uint256 orderIndexSeed) external {
        if (helperOrderIds.length == 0) return;
        uint256 orderId = helperOrderIds[_bound(orderIndexSeed, 0, helperOrderIds.length - 1)];
        if (vault.getRedeemOrder(orderId).status != OrderStatus.Pending) return;

        uint256 outsiderBalBefore = asset.balanceOf(outsider);
        vm.prank(outsider);
        try helper.fillAndFinalizeRedeemOrder(orderId, type(uint128).max, block.timestamp + 1 days) {
            unauthorizedAssetMoveObserved = true;
        } catch {}
        if (asset.balanceOf(outsider) != outsiderBalBefore) {
            unauthorizedAssetMoveObserved = true;
        }
    }

    /// @dev `vaultFiller` (the legacy-EOA analogue) fills directly on the vault, leaving the order
    /// Filled -- at which point an escrowed fee must NOT be settleable (I2d). The order is then
    /// finalized either through the helper's permissionless passthrough (which settles the fee
    /// inline; I9-tracked) or straight at the vault by the owner (fee left for `settleFee`).
    /// I6's "always finalizable when Filled" applies to both.
    function fillOnVaultThenFinalize(uint256 orderIndexSeed, uint256 finalizerSeed) external {
        if (helperOrderIds.length == 0) return;
        uint256 orderId = helperOrderIds[_bound(orderIndexSeed, 0, helperOrderIds.length - 1)];
        Order memory order = vault.getRedeemOrder(orderId);
        if (order.status != OrderStatus.Pending) return;

        asset.mint(vaultFiller, type(uint128).max);
        vm.prank(vaultFiller);
        try vault.fillRedeemOrder(orderId) {}
        catch {
            return;
        }
        vaultFillCount++;

        // Filled with an escrowed fee: the payout has not happened, so settling must revert.
        if (helper.orderFeeTokens(orderId) != 0) {
            try helper.settleFee(orderId) {
                earlyFeeSettleObserved = true;
            } catch {}
        }

        if (vault.paused()) return; // finalize is expected to fail while paused -- not a violation

        bool viaHelper = finalizerSeed % 2 == 0;
        address finalizer = _actor(finalizerSeed / 2);
        uint256 receiverBalBefore = asset.balanceOf(order.receiver);
        if (viaHelper) {
            // Filled below the owner's floor by another filler: the helper must refuse, and the
            // owner must still be able to finalize at the vault.
            if (vault.getRedeemOrder(orderId).assets < helper.orderMinAssetsOut(orderId)) {
                vm.prank(finalizer);
                try helper.finalizeRedeemOrder(orderId) {
                    unexpectedFinalizeFailures++;
                } catch (bytes memory err) {
                    if (bytes4(err) != YuzuRedeemOrderHelper.MinAssetsOutNotMet.selector) unexpectedFinalizeFailures++;
                }
                vm.prank(order.owner);
                try vault.finalizeRedeemOrder(orderId) {
                    finalizedAtVaultCount++;
                } catch {
                    unexpectedFinalizeFailures++;
                }
                return;
            }
            vm.prank(finalizer);
            try helper.finalizeRedeemOrder(orderId) {
                assetsSettledAccordingToVault += vault.getRedeemOrder(orderId).assets;
                actualAssetsDeliveredToReceivers += asset.balanceOf(order.receiver) - receiverBalBefore;
                finalizedViaHelperCount++;
            } catch {
                unexpectedFinalizeFailures++;
            }
        } else {
            vm.prank(order.owner);
            try vault.finalizeRedeemOrder(orderId) {
                finalizedAtVaultCount++;
            } catch {
                unexpectedFinalizeFailures++;
            }
        }
    }

    /// @dev The order's owner cancels directly on the vault once `dueTime` has passed and the
    /// vault is unpaused -- I6's second half. The escrowed fee is then refundable via `settleFee`.
    function userCancelAfterDue(uint256 orderIndexSeed) external {
        if (helperOrderIds.length == 0) return;
        uint256 orderId = helperOrderIds[_bound(orderIndexSeed, 0, helperOrderIds.length - 1)];
        Order memory order = vault.getRedeemOrder(orderId);
        if (order.status != OrderStatus.Pending) return;
        if (vault.paused() || block.timestamp < order.dueTime) return;

        vm.prank(order.owner);
        try vault.cancelRedeemOrder(orderId) {
            userCancelCount++;
        } catch {
            unexpectedUserCancelFailures++;
        }
    }

    /// @dev `ADMIN_ROLE` cancels an order the helper controls, or -- for `directOrderIds` -- one
    /// it deliberately does not. I8: the latter must never succeed.
    function cancelOwnOrder(uint256 seed, bool useDirect) external {
        uint256[] storage pool = useDirect ? directOrderIds : helperOrderIds;
        if (pool.length == 0) return;
        uint256 orderId = pool[_bound(seed, 0, pool.length - 1)];
        Order memory order = vault.getRedeemOrder(orderId);
        if (order.status != OrderStatus.Pending) return;

        vm.prank(admin);
        try helper.cancelOwnRedeemOrder(orderId) {
            adminCancelCount++;
            if (order.controller != address(helper)) {
                illegalCancelObserved = true;
            }
        } catch {}
    }

    /// @dev Third-party donor: dust with no role anywhere, no interaction beyond a raw transfer.
    /// Mandatory -- without it I1 proves nothing about donation tolerance.
    function donate(uint256 amountSeed) external {
        uint256 amount = _bound(amountSeed, 1, 1e6);
        asset.mint(address(helper), amount);
        totalDonated += amount;
    }

    function setRedeemOrderFee(uint256 feePpmSeed) external {
        uint256 feePpm = _bound(feePpmSeed, 0, 1_000_000);
        vm.prank(feeManager);
        vault.setRedeemOrderFee(feePpm);
    }

    /// @dev Admin moves the helper fee rate and recipient mid-flight, so escrowed fees get settled
    /// (or refunded) against a rate and recipient different from the ones they were taken at.
    function setHelperFee(uint256 bpsSeed, uint256 recipientSeed) external {
        uint16 bps = uint16(_bound(bpsSeed, 0, helper.MAX_FEE_BPS()));
        address recipient = (bps == 0 && recipientSeed % 2 == 0) ? address(0) : _actor(recipientSeed);
        vm.prank(admin);
        helper.setFee(bps, recipient);
    }

    /// @dev Anyone settles the escrowed fee of an order the vault has already resolved (I2c). On an
    /// order still Pending or Filled the same call must revert instead (I2d).
    function settleFeeFor(uint256 orderIndexSeed) external {
        if (helperOrderIds.length == 0) return;
        uint256 orderId = helperOrderIds[_bound(orderIndexSeed, 0, helperOrderIds.length - 1)];
        if (helper.orderFeeTokens(orderId) == 0) return;
        OrderStatus status = vault.getRedeemOrder(orderId).status;
        bool resolved = status != OrderStatus.Pending && status != OrderStatus.Filled;

        vm.prank(outsider);
        try helper.settleFee(orderId) {
            if (resolved) settleFeeCount++;
            else earlyFeeSettleObserved = true;
        } catch {
            if (resolved) unexpectedSettleFeeFailures++;
        }
    }

    function pauseVault(bool pause_) external {
        vm.startPrank(admin);
        if (pause_) {
            if (!vault.paused()) vault.pause();
        } else {
            if (vault.paused()) vault.unpause();
        }
        vm.stopPrank();
    }

    function pauseHelper(bool pause_) external {
        vm.startPrank(admin);
        if (pause_) {
            if (!helper.paused()) helper.pause();
        } else {
            if (helper.paused()) helper.unpause();
        }
        vm.stopPrank();
    }

    /// @dev The list manager adds or removes one actor, including one with orders in flight.
    function setWhitelisted(uint256 actorSeed, bool allowed) external {
        address[] memory accounts = new address[](1);
        accounts[0] = _actor(actorSeed);
        vm.prank(admin);
        helper.setWhitelisted(accounts, allowed);
    }

    function setWhitelistEnabled(bool enabled) external {
        vm.prank(admin);
        helper.setWhitelistEnabled(enabled);
    }

    function warp(uint256 secondsForward) external {
        vm.warp(block.timestamp + _bound(secondsForward, 0, 3 days));
    }
}

/// @dev Invariants under fuzzed sequences over the deployed base helper, against a single ILP V3
/// fixture. yzUSD V3 coverage stays in the parameterised unit files.
contract YuzuRedeemOrderHelperInvariantTest is YuzuV3TestBase {
    YuzuRedeemOrderHelper internal helper;
    YuzuRedeemOrderHelperInvariantHandler internal handler;

    address internal vaultFiller = makeAddr("invariantVaultFiller");
    address internal outsider = makeAddr("invariantOutsider");

    function setUp() public {
        asset = _newAsset();
        yzilp = _deployYuzuILPV3();

        vm.startPrank(admin);
        yzilp.grantRole(FEE_MANAGER_ROLE, feeManager);
        yzilp.grantRole(PAUSE_MANAGER_ROLE, admin);
        yzilp.grantRole(ORDER_FILLER_ROLE, vaultFiller);
        yzilp.setIsMintRestricted(false);
        yzilp.setIsRedeemRestricted(false);
        vm.stopPrank();

        helper = new YuzuRedeemOrderHelper(address(yzilp), address(asset), admin, admin);

        vm.startPrank(admin);
        yzilp.grantRole(ORDER_FILLER_ROLE, address(helper));
        helper.grantRole(helper.PAUSE_MANAGER_ROLE(), admin);
        helper.grantRole(helper.LIMIT_MANAGER_ROLE(), admin);
        helper.grantRole(helper.CANCEL_MANAGER_ROLE(), admin);
        helper.setLimits(type(uint256).max, type(uint256).max, type(uint256).max);
        vm.stopPrank();

        vm.prank(vaultFiller);
        asset.approve(address(yzilp), type(uint256).max);

        handler =
            new YuzuRedeemOrderHelperInvariantHandler(yzilp, helper, asset, admin, feeManager, vaultFiller, outsider);
        targetContract(address(handler));
    }

    /// I1 -- a delta invariant, never absolute zero: the helper's live asset balance must equal
    /// exactly what third parties have donated to it. Every helper operation is required by source
    /// to return the helper to its own entry balance, so any drift here means some call left behind
    /// (or took) more than it should have.
    function invariantTest_I1_HelperAssetBalanceMatchesDonationsOnly() public view {
        assertEq(asset.balanceOf(address(helper)), handler.totalDonated(), "! helper balance == totalDonated");
    }

    /// I2 -- the helper's vault-share balance always covers what it owes in escrowed fees. It may
    /// exceed it (a share donation), never fall below it.
    function invariantTest_I2_HelperHoldsAtLeastEscrowedFeeShares() public view {
        assertGe(
            yzilp.balanceOf(address(helper)), helper.totalEscrowedFeeShares(), "! shareBalance(helper) >= escrowed"
        );
    }

    /// I2b -- the escrow total is exactly the sum of the per-order fee records over every order the
    /// helper created.
    function invariantTest_I2b_EscrowTotalEqualsSumOfOrderFees() public view {
        uint256 sum;
        uint256 n = handler.helperOrderCount();
        for (uint256 i = 0; i < n; i++) {
            sum += helper.orderFeeTokens(handler.helperOrderIds(i));
        }
        assertEq(helper.totalEscrowedFeeShares(), sum, "! totalEscrowedFeeShares == sum(orderFeeTokens)");
    }

    /// I2c -- `settleFee` never fails on an order whose fee is escrowed and whose vault status is
    /// Finalized or Cancelled.
    function invariantTest_I2c_SettleFeeNeverFailsOnceResolved() public view {
        assertEq(handler.unexpectedSettleFeeFailures(), 0, "! settleFee failed on a resolved order");
    }

    /// I2d -- `settleFee` never succeeds on an order whose escrowed fee is still waiting on a
    /// Pending or Filled order.
    function invariantTest_I2d_SettleFeeRevertsWhilePendingOrFilled() public view {
        assertFalse(handler.earlyFeeSettleObserved(), "! settleFee succeeded before the order resolved");
    }

    /// I3 -- no standing allowance to the vault outside of a call.
    function invariantTest_I3_NoStandingAllowanceToVault() public view {
        assertEq(asset.allowance(address(helper), address(yzilp)), 0, "! allowance(helper, vault) == 0");
    }

    /// I4 -- no caller lacking `FILLER_ROLE` ever moved an asset through the helper.
    function invariantTest_I4_NoUnauthorizedAssetMove() public view {
        assertFalse(handler.unauthorizedAssetMoveObserved(), "! unauthorizedAssetMoveObserved == false");
    }

    /// I5 -- every order the helper created has `owner` == the original caller and `controller` ==
    /// the helper.
    function invariantTest_I5_HelperOrdersOwnerAndControllerCorrect() public view {
        uint256 count = handler.helperOrderCount();
        for (uint256 i = 0; i < count; i++) {
            uint256 orderId = handler.helperOrderIds(i);
            Order memory order = yzilp.getRedeemOrder(orderId);
            assertEq(order.controller, address(helper), "! order.controller == helper");
            assertEq(order.owner, handler.expectedOwnerOf(orderId), "! order.owner == expected caller");
        }
    }

    /// I6 -- a helper-routed order is always finalizable (through the helper or at the vault) when
    /// Filled, and its owner can always cancel on the vault after `dueTime` once unpaused.
    function invariantTest_I6_FinalizeAndDueCancelNeverUnexpectedlyFail() public view {
        assertEq(handler.unexpectedFinalizeFailures(), 0, "! unexpectedFinalizeFailures == 0");
        assertEq(handler.unexpectedUserCancelFailures(), 0, "! unexpectedUserCancelFailures == 0");
    }

    /// I8 -- the helper never cancels an order it does not control (`ORDER_FILLER_ROLE`'s
    /// force-cancel power never becomes a primitive over the wider order book).
    function invariantTest_I8_NeverCancelsForeignOrder() public view {
        assertFalse(handler.illegalCancelObserved(), "! illegalCancelObserved == false");
    }

    /// I9 -- assets paid out through the helper equal the sum of settled `order.assets` finalized
    /// through it, measured two independent ways: what the vault recorded as settled, and what
    /// receivers actually received. No skim, no shortfall, across every fee mutation fuzzed above.
    function invariantTest_I9_AssetsDeliveredMatchVaultSettledAmounts() public view {
        assertEq(
            handler.actualAssetsDeliveredToReceivers(),
            handler.assetsSettledAccordingToVault(),
            "! assetsDelivered == assetsSettledAccordingToVault"
        );
    }

    /// I10 -- while the whitelist is on, the helper never creates or fills an order for an owner
    /// off the list, however the list and the switch were churned around orders in flight. I6
    /// above runs over the same churn, so delisting never blocks finalize or the owner's cancel.
    function invariantTest_I10_WhitelistGatesCreateAndFill() public view {
        assertFalse(handler.gatedOwnerServedObserved(), "! helper served an owner off the whitelist");
    }
}
