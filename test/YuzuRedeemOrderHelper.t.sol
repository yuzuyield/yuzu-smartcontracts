// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {Order, OrderStatus} from "../src/interfaces/proto/IYuzuOrderBookDefinitions.sol";
import {IYuzuOrderBookDefinitions} from "../src/interfaces/proto/IYuzuOrderBookDefinitions.sol";
import {IYuzuProto, IYuzuProtoV2} from "../src/interfaces/proto/IYuzuProto.sol";
import {IYuzuProtoDefinitions} from "../src/interfaces/proto/IYuzuProtoDefinitions.sol";
import {IYuzuRedeemOrderHelper} from "../src/interfaces/IYuzuRedeemOrderHelper.sol";
import {YuzuRedeemOrderHelper} from "../src/helpers/YuzuRedeemOrderHelper.sol";
import {
    FEE_MANAGER_ROLE,
    NAV_MANAGER_ROLE,
    ORDER_FILLER_ROLE,
    PAUSE_MANAGER_ROLE,
    POOL_MANAGER_ROLE,
    REDEEMER_ROLE,
    RESTRICTION_MANAGER_ROLE
} from "./helpers/TestRoles.sol";
import {YuzuV3TestBase} from "./helpers/YuzuV3TestBase.sol";

/// @dev Minimal deposit surface shared by YuzuILPV3 and YuzuUSDV3, used to parameterize tests
/// across both vaults without a generic ERC4626 dependency.
interface IDepositable {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}

/// @dev A self-contained fake vault exposing only the functions {YuzuRedeemOrderHelper} calls,
/// with `previewRedeemOrder` set to always revert (F1, phase-04 requirement). If the helper's
/// settlement path ever called it, `test_F1_SettlementNeverCallsPreviewRedeemOrder` below would
/// revert instead of passing -- the whole point of the property.
contract RevertingPreviewVault {
    using SafeERC20 for IERC20;

    IERC20 internal immutable _asset;
    mapping(uint256 => Order) internal _orders;
    uint256 public orderCount;

    constructor(address asset_) {
        _asset = IERC20(asset_);
    }

    function asset() external view returns (address) {
        return address(_asset);
    }

    /// @dev The helper probes `isUpdatingPool()` at construction, finds it absent here, and falls
    /// back to the yzUSD-family predicate. This fake never stages a restatement, so settlement is
    /// always open.
    function canRedeem(address) external pure returns (bool) {
        return true;
    }

    function createRedeemOrderWithMaxFee(uint256 tokens, address receiver, address owner, uint256)
        external
        returns (uint256 orderId)
    {
        orderId = orderCount++;
        _orders[orderId] = Order({
            assets: tokens,
            tokens: tokens,
            owner: owner,
            receiver: receiver,
            controller: msg.sender,
            dueTime: uint40(block.timestamp + 1 days),
            status: OrderStatus.Pending,
            feePpm: 0
        });
    }

    function fillRedeemOrder(uint256 orderId) external {
        Order storage order = _orders[orderId];
        require(order.status == OrderStatus.Pending, "not pending");
        order.status = OrderStatus.Filled;
        _asset.safeTransferFrom(msg.sender, address(this), order.assets);
    }

    function finalizeRedeemOrder(uint256 orderId) external {
        Order storage order = _orders[orderId];
        require(order.status == OrderStatus.Filled, "not filled");
        order.status = OrderStatus.Finalized;
        _asset.safeTransfer(order.receiver, order.assets);
    }

    function getRedeemOrder(uint256 orderId) external view returns (Order memory) {
        return _orders[orderId];
    }

    function previewRedeemOrder(uint256) external pure returns (uint256) {
        revert("previewRedeemOrder must never be called by the helper's settlement path");
    }
}

/// @dev Phase 2 smoke suite. Property tests for F1 (fee-mutation matrix) and F2 (donation DoS) are
/// the load-bearing ones here; the full invariant/fuzz/fork suite is Phase 4.
contract YuzuRedeemOrderHelperTest is YuzuV3TestBase {
    address internal helperFiller = makeAddr("helperFiller");

    YuzuRedeemOrderHelper internal ilpHelper;
    YuzuRedeemOrderHelper internal usdHelper;

    function setUp() public {
        asset = _newAsset();
        asset.mint(user, 10_000_000e6);
        asset.mint(other, 10_000_000e6);
        asset.mint(helperFiller, 10_000_000e6);

        yzilp = _deployYuzuILPV3();
        yzusd = _deployYuzuUSDV3();

        vm.startPrank(admin);
        yzilp.grantRole(FEE_MANAGER_ROLE, feeManager);
        yzilp.grantRole(ORDER_FILLER_ROLE, filler);
        yzilp.setIsMintRestricted(false);
        yzilp.grantRole(POOL_MANAGER_ROLE, admin);
        yzilp.setIsRedeemRestricted(false);

        yzusd.grantRole(FEE_MANAGER_ROLE, feeManager);
        yzusd.grantRole(ORDER_FILLER_ROLE, filler);
        yzusd.setIsMintRestricted(false);
        yzusd.setIsRedeemRestricted(false);
        vm.stopPrank();

        _approve(user, address(yzilp));
        _approve(other, address(yzilp));
        _approve(user, address(yzusd));
        _approve(other, address(yzusd));

        ilpHelper = new YuzuRedeemOrderHelper(address(yzilp), address(asset), admin, admin);
        usdHelper = new YuzuRedeemOrderHelper(address(yzusd), address(asset), admin, admin);

        vm.startPrank(admin);
        yzilp.grantRole(ORDER_FILLER_ROLE, address(ilpHelper));
        yzusd.grantRole(ORDER_FILLER_ROLE, address(usdHelper));
        ilpHelper.grantRole(ilpHelper.FILLER_ROLE(), helperFiller);
        usdHelper.grantRole(usdHelper.FILLER_ROLE(), helperFiller);
        ilpHelper.grantRole(ilpHelper.PAUSE_MANAGER_ROLE(), admin);
        usdHelper.grantRole(usdHelper.PAUSE_MANAGER_ROLE(), admin);
        ilpHelper.setWhitelistEnabled(false);
        usdHelper.setWhitelistEnabled(false);
        ilpHelper.grantRole(ilpHelper.LIMIT_MANAGER_ROLE(), admin);
        usdHelper.grantRole(usdHelper.LIMIT_MANAGER_ROLE(), admin);
        ilpHelper.grantRole(ilpHelper.CANCEL_MANAGER_ROLE(), admin);
        usdHelper.grantRole(usdHelper.CANCEL_MANAGER_ROLE(), admin);
        ilpHelper.setLimits(type(uint256).max, type(uint256).max, type(uint256).max);
        usdHelper.setLimits(type(uint256).max, type(uint256).max, type(uint256).max);
        vm.stopPrank();

        vm.startPrank(user);
        yzilp.approve(address(ilpHelper), type(uint256).max);
        yzusd.approve(address(usdHelper), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(helperFiller);
        asset.approve(address(ilpHelper), type(uint256).max);
        asset.approve(address(usdHelper), type(uint256).max);
        vm.stopPrank();
    }

    // --- shared helpers -----------------------------------------------------------------------

    /// @dev Deposits `assets` for `user`, creates a redeem order for the full share balance through
    /// `helper_`, and snapshots `previewRedeemOrder` immediately after creation — before any fee
    /// mutation — as the ground truth for what the *stamped* fee committed to.
    function _createOrderAndSnapshotExpected(IYuzuProto vault_, YuzuRedeemOrderHelper helper_, uint256 assets)
        internal
        returns (uint256 orderId, uint256 expectedAssets)
    {
        vm.prank(user);
        uint256 shares = IDepositable(address(vault_)).deposit(assets, user);

        vm.prank(user);
        orderId = helper_.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        expectedAssets = vault_.previewRedeemOrder(shares);
    }

    function _happyPath(IYuzuProto vault_, YuzuRedeemOrderHelper helper_) internal {
        (uint256 orderId, uint256 expectedAssets) = _createOrderAndSnapshotExpected(vault_, helper_, 100e6);

        uint256 receiverBalBefore = asset.balanceOf(user);
        vm.prank(helperFiller);
        helper_.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 5e6, block.timestamp + 1 days);

        Order memory order = vault_.getRedeemOrder(orderId);
        assertEq(uint256(order.status), uint256(OrderStatus.Finalized), "order not finalized");
        assertEq(order.controller, address(helper_), "controller drifted");
        assertEq(order.owner, user, "owner drifted");
        assertEq(asset.balanceOf(user), receiverBalBefore + expectedAssets, "receiver did not receive settled assets");
        assertNoResidualDelta(address(helper_), 0);
    }

    /// @dev The fee-mutation matrix (F1, F15): the property that actually distinguishes the fixed
    /// design from the broken one is `redeemOrderFeePpm` moving between order creation and fill.
    function _feeMutationMatrix(IYuzuProto vault_, YuzuRedeemOrderHelper helper_) internal {
        // Row 1: no fee change -- settles at the stamped fee, filler refunded the unused amount.
        {
            (uint256 orderId, uint256 expectedAssets) = _createOrderAndSnapshotExpected(vault_, helper_, 100e6);
            uint256 fillerBalBefore = asset.balanceOf(helperFiller);

            vm.prank(helperFiller);
            helper_.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

            assertEq(uint256(vault_.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
            assertEq(vault_.getRedeemOrder(orderId).assets, expectedAssets, "row1: mispriced");
            assertEq(asset.balanceOf(helperFiller), fillerBalBefore - expectedAssets, "row1: refund wrong");
        }

        // Row 2: fee raised after creation -- the broken design (previewRedeemOrder at fill time)
        // would price this differently; the fix settles at the stamped fee regardless.
        {
            (uint256 orderId, uint256 expectedAssets) = _createOrderAndSnapshotExpected(vault_, helper_, 100e6);

            vm.prank(feeManager);
            vault_.setRedeemOrderFee(50_000); // 5%, raised from 0

            vm.prank(helperFiller);
            helper_.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

            assertEq(vault_.getRedeemOrder(orderId).assets, expectedAssets, "row2: fee raise altered settlement");

            vm.prank(feeManager);
            vault_.setRedeemOrderFee(0);
        }

        // Row 3: fee lowered after creation -- same property, opposite direction.
        {
            vm.prank(feeManager);
            vault_.setRedeemOrderFee(50_000);

            (uint256 orderId, uint256 expectedAssets) = _createOrderAndSnapshotExpected(vault_, helper_, 100e6);

            vm.prank(feeManager);
            vault_.setRedeemOrderFee(0);

            vm.prank(helperFiller);
            helper_.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

            assertEq(vault_.getRedeemOrder(orderId).assets, expectedAssets, "row3: fee lower altered settlement");
        }

        // Row 4: maxAssets under the true settled amount -- reverts cleanly, no state change.
        {
            (uint256 orderId, uint256 expectedAssets) = _createOrderAndSnapshotExpected(vault_, helper_, 100e6);

            vm.prank(feeManager);
            vault_.setRedeemOrderFee(50_000);

            uint256 fillerBalBefore = asset.balanceOf(helperFiller);
            uint256 helperBalBefore = asset.balanceOf(address(helper_));

            vm.prank(helperFiller);
            vm.expectRevert();
            helper_.fillAndFinalizeRedeemOrder(orderId, expectedAssets - 1, block.timestamp + 1 days);

            assertEq(
                uint256(vault_.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending), "row4: state changed"
            );
            assertEq(asset.balanceOf(helperFiller), fillerBalBefore, "row4: filler balance changed");
            assertEq(asset.balanceOf(address(helper_)), helperBalBefore, "row4: helper balance changed");

            vm.prank(feeManager);
            vault_.setRedeemOrderFee(0);
        }
    }

    // --- 1. happy path, both vaults (also proves phase-01's cross-vault interface compile) ------

    function test_ILP_HappyPath_FillAndFinalize() public {
        _happyPath(IYuzuProto(address(yzilp)), ilpHelper);
    }

    function test_USD_HappyPath_FillAndFinalize() public {
        _happyPath(IYuzuProto(address(yzusd)), usdHelper);
    }

    // --- 2. F1 fee-mutation matrix, both vaults --------------------------------------------------

    function test_ILP_FeeMutationMatrix() public {
        _feeMutationMatrix(IYuzuProto(address(yzilp)), ilpHelper);
    }

    function test_USD_FeeMutationMatrix() public {
        _feeMutationMatrix(IYuzuProto(address(yzusd)), usdHelper);
    }

    // --- 3. F2 donation DoS -----------------------------------------------------------------------

    function test_DonationDoesNotBreakFill() public {
        asset.mint(address(ilpHelper), 1); // a third party donates 1 wei of dust

        (uint256 orderId, uint256 expectedAssets) =
            _createOrderAndSnapshotExpected(IYuzuProto(address(yzilp)), ilpHelper, 100e6);

        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        // Delta, not absolute zero (F2): the exit balance equals the entry balance, 1 wei.
        assertNoResidualDelta(address(ilpHelper), 1);
    }

    // --- 4. F3/F4 cancel scope ----------------------------------------------------------------

    function test_CancelOwnRedeemOrder_SucceedsWhilePausedAndBeforeDueTime() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        vm.startPrank(admin);
        yzilp.grantRole(PAUSE_MANAGER_ROLE, admin);
        yzilp.pause();
        vm.stopPrank();

        // Still well before dueTime (fillWindow = 1 days, no warp) and the vault is paused -- a
        // plain owner cancel would revert on both counts (YuzuV3FacetBase.sol:149-157).
        vm.prank(admin);
        ilpHelper.cancelOwnRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Cancelled));
    }

    function test_CancelOwnRedeemOrder_Revert_ThirdPartyOrder() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        // Created directly on the vault: controller = user, not the helper.
        vm.prank(user);
        uint256 orderId = yzilp.createRedeemOrder(shares, user, user);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.OrderNotControlledByHelper.selector, orderId, user)
        );
        ilpHelper.cancelOwnRedeemOrder(orderId);
    }

    // --- 5. role gate -----------------------------------------------------------------------------

    function test_FillAndFinalize_Revert_NotFillerRole() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        vm.prank(other);
        asset.approve(address(ilpHelper), type(uint256).max);
        uint256 balBefore = asset.balanceOf(other);

        bytes32 fillerRole = ilpHelper.FILLER_ROLE();
        vm.prank(other);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, other, fillerRole)
        );
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, 1_000e6, block.timestamp + 1 days);

        assertEq(asset.balanceOf(other), balBefore, "asset moved despite missing FILLER_ROLE");
    }

    // --- 6. controller check refuses both fill and cancel ------------------------------------------

    function test_FillAndFinalize_Revert_OrderNotControlledByHelper() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.prank(user);
        uint256 orderId = yzilp.createRedeemOrder(shares, user, user); // controller = user

        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.OrderNotControlledByHelper.selector, orderId, user)
        );
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, 1_000e6, block.timestamp + 1 days);
    }

    // --- 7. user rights preserved ---------------------------------------------------------------

    function test_UserCanFinalizeThemselves() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        // Filled directly on the vault by the ordinary vault-level filler, bypassing the helper
        // entirely, to prove the user is never locked into the helper's own finalize path.
        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Filled));

        vm.prank(user);
        yzilp.finalizeRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    function test_UserCanCancelOnVaultAfterDueTimeWhenNotPaused() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        vm.warp(block.timestamp + yzilp.fillWindow());

        vm.prank(user);
        yzilp.cancelRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Cancelled));
    }

    // --- additional phase-02 success criteria ----------------------------------------------------

    function test_FillAndFinalize_Revert_WhenVaultPaused() public {
        (uint256 orderId, uint256 expectedAssets) =
            _createOrderAndSnapshotExpected(IYuzuProto(address(yzilp)), ilpHelper, 100e6);

        vm.startPrank(admin);
        yzilp.grantRole(PAUSE_MANAGER_ROLE, admin);
        yzilp.pause();
        vm.stopPrank();

        uint256 fillerBalBefore = asset.balanceOf(helperFiller);

        // fillRedeemOrder has no pause check, but finalizeRedeemOrder does; the whole call reverts
        // atomically -- filled-but-not-finalized is never observable state.
        vm.prank(helperFiller);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 5e6, block.timestamp + 1 days);

        assertEq(asset.balanceOf(helperFiller), fillerBalBefore, "filler balance changed despite revert");
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending), "order state changed");
    }

    function test_FillAndFinalize_Revert_ExecDeadlineExpired() public {
        (uint256 orderId,) = _createOrderAndSnapshotExpected(IYuzuProto(address(yzilp)), ilpHelper, 100e6);

        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(
                YuzuRedeemOrderHelper.ExecDeadlineExpired.selector, block.timestamp - 1, block.timestamp
            )
        );
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, 1_000e6, block.timestamp - 1);
    }

    function test_CreateRedeemOrderWithMaxFee_Revert_FeeOverMax() public {
        vm.prank(feeManager);
        yzilp.setRedeemOrderFee(50_000); // 5%

        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IYuzuProtoDefinitions.FeeOverMaxFee.selector, 50_000, 10_000));
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 10_000, 100, 1); // 1% ceiling, under the 5% live fee
    }

    function test_Pause_BlocksCreationOnly() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(200e6, user);

        vm.prank(admin);
        ilpHelper.pause();

        vm.prank(user);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        vm.prank(admin);
        ilpHelper.unpause();

        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending));
    }

    function test_PauseSplit_PauserCannotUnpause() public {
        address pauser = makeAddr("pauser");
        bytes32 pauseRole = ilpHelper.PAUSE_MANAGER_ROLE();
        bytes32 adminRole = ilpHelper.ADMIN_ROLE();
        vm.prank(admin);
        ilpHelper.grantRole(pauseRole, pauser);

        vm.prank(pauser);
        ilpHelper.pause();

        vm.prank(pauser);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, adminRole)
        );
        ilpHelper.unpause();

        vm.prank(admin);
        ilpHelper.unpause();
        assertFalse(ilpHelper.paused());
    }

    /// @dev The helper has no allowlist of its own: the vault's REDEEMER_ROLE is the only owner gate.
    /// On a redeem-restricted vault a non-REDEEMER owner cannot create through the helper (the vault
    /// reverts), and becomes able to once the vault grants the role.
    function test_RedeemRestrictedVault_NonRedeemerCannotCreateThroughHelper() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(200e6, user);

        vm.prank(admin);
        yzilp.setIsRedeemRestricted(true);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IYuzuOrderBookDefinitions.ExceededMaxRedeemOrder.selector, user, shares, 0)
        );
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        assertEq(yzilp.balanceOf(user), shares, "shares moved despite the revert");

        vm.startPrank(admin);
        yzilp.grantRole(RESTRICTION_MANAGER_ROLE, admin);
        yzilp.grantRole(REDEEMER_ROLE, user);
        vm.stopPrank();

        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        uint256 expected = yzilp.previewRedeemOrder(shares);
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expected + 5e6, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    /// @dev Creates an order through `ilpHelper` at `feeBps` 30 for the whole share balance of
    /// `user` and returns everything the fee regression tests below assert against.
    function _createFeeOrder(address collector)
        internal
        returns (uint256 orderId, uint256 shares, uint256 feeTokens, uint256 expected)
    {
        vm.prank(admin);
        ilpHelper.setFee(30, collector);
        vm.prank(user);
        shares = yzilp.deposit(100e6 + 3, user);

        feeTokens = Math.mulDiv(shares, 30, 10_000, Math.Rounding.Floor);
        expected = yzilp.previewRedeemOrder(shares - feeTokens);

        vm.prank(user);
        orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, expected);
    }

    /// @dev (a) The fee is pulled into the helper at creation and recorded; the order is net of it
    /// and the owner needs nothing further.
    function test_HelperFee_EscrowedAtCreation() public {
        address collector = makeAddr("collector");
        (uint256 orderId, uint256 shares, uint256 feeTokens,) = _createFeeOrder(collector);

        assertGt(feeTokens, 0, "test setup: fee must be non-zero");
        assertEq(feeTokens, shares * 30 / 10_000, "fee is not floor(tokens * bps / 1e4)");
        assertEq(ilpHelper.orderFeeTokens(orderId), feeTokens, "fee not recorded");
        assertEq(ilpHelper.totalEscrowedFeeShares(), feeTokens, "escrow total not updated");
        assertEq(yzilp.getRedeemOrder(orderId).tokens, shares - feeTokens, "order not net of fee");
        assertEq(yzilp.balanceOf(user), 0, "owner balance should be down by the full tokens");
        assertEq(yzilp.balanceOf(address(ilpHelper)), feeTokens, "helper does not hold the fee");
        assertEq(yzilp.balanceOf(collector), 0, "fee paid out before any redemption");
    }

    /// @dev (b) Filling through the helper pays the recipient exactly the escrowed fee, with a
    /// `ChargedFee` carrying the order id, and the escrow returns to zero.
    function test_HelperFee_FillPaysRecipient_EscrowCleared() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens, uint256 expected) = _createFeeOrder(collector);

        uint256 userAssetsBefore = asset.balanceOf(user);
        uint256 fillerBefore = asset.balanceOf(helperFiller);

        vm.expectEmit(true, true, true, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.ChargedFee(orderId, user, collector, feeTokens);
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expected + 5e6, block.timestamp + 1 days);

        assertEq(yzilp.balanceOf(collector), feeTokens, "fee shares not delivered");
        assertEq(yzilp.balanceOf(user), 0, "owner should hold no shares");
        assertEq(ilpHelper.orderFeeTokens(orderId), 0, "fee record not cleared");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
        assertEq(yzilp.balanceOf(address(ilpHelper)), 0, "helper still holds shares");
        assertEq(asset.balanceOf(user), userAssetsBefore + expected, "user payout");
        assertEq(asset.balanceOf(helperFiller), fillerBefore - expected, "filler debit");
        assertNoResidualDelta(address(ilpHelper), 0);
    }

    /// @dev (c) The fee is already in escrow, so the owner moving shares or revoking the allowance
    /// after creation cannot stop the fill.
    function test_HelperFee_OwnerMovesSharesAndRevokesAllowance_FillStillSucceeds() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens, uint256 expected) = _createFeeOrder(collector);

        vm.startPrank(user);
        uint256 extra = yzilp.deposit(50e6, user);
        yzilp.transfer(other, extra);
        yzilp.approve(address(ilpHelper), 0);
        vm.stopPrank();
        assertEq(yzilp.balanceOf(user), 0, "test setup: owner should hold nothing");

        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expected + 5e6, block.timestamp + 1 days);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        assertEq(yzilp.balanceOf(collector), feeTokens, "fee not paid");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev (d) Admin `cancelOwnRedeemOrder` refunds the whole escrowed fee: the owner ends with
    /// exactly the shares it started with.
    function test_HelperFee_CancelOwn_RefundsFullFee() public {
        address collector = makeAddr("collector");
        (uint256 orderId, uint256 shares, uint256 feeTokens,) = _createFeeOrder(collector);

        vm.expectEmit(true, true, false, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.RefundedFee(orderId, user, feeTokens);
        vm.prank(admin);
        ilpHelper.cancelOwnRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Cancelled));
        assertEq(yzilp.balanceOf(user), shares, "owner did not get the original shares back");
        assertEq(yzilp.balanceOf(collector), 0, "fee recipient paid for a cancelled order");
        assertEq(yzilp.balanceOf(address(ilpHelper)), 0, "helper still holds shares");
        assertEq(ilpHelper.orderFeeTokens(orderId), 0, "fee record survived cancelOwn");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev (e) The owner cancels at the vault after dueTime: the fee stays in escrow until anyone
    /// calls `settleFee`, which refunds it. The order is no longer fillable.
    function test_HelperFee_OwnerVaultCancel_ThenSettleFeeRefunds() public {
        address collector = makeAddr("collector");
        (uint256 orderId, uint256 shares, uint256 feeTokens,) = _createFeeOrder(collector);

        vm.warp(block.timestamp + yzilp.fillWindow());
        vm.prank(user);
        yzilp.cancelRedeemOrder(orderId);

        assertEq(yzilp.balanceOf(user), shares - feeTokens, "vault cancel should return the net tokens only");
        assertEq(ilpHelper.totalEscrowedFeeShares(), feeTokens, "fee should still be escrowed");

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.OrderNotPending.selector, orderId));
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, 1_000e6, block.timestamp + 1 days);

        vm.expectEmit(true, true, false, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.RefundedFee(orderId, user, feeTokens);
        vm.prank(other);
        ilpHelper.settleFee(orderId);

        assertEq(yzilp.balanceOf(user), shares, "owner did not get the original shares back");
        assertEq(yzilp.balanceOf(collector), 0, "fee recipient paid for a cancelled order");
        assertEq(yzilp.balanceOf(address(ilpHelper)), 0, "helper still holds shares");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev (f) Another vault ORDER_FILLER fills directly; the helper's permissionless finalize
    /// passthrough settles the escrowed fee inline and pays the recipient.
    function test_HelperFee_FilledElsewhere_HelperFinalizeChargesRecipient() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens,) = _createFeeOrder(collector);

        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);

        vm.expectEmit(true, true, true, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.ChargedFee(orderId, user, collector, feeTokens);
        vm.prank(other);
        ilpHelper.finalizeRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        assertEq(yzilp.balanceOf(collector), feeTokens, "finalize passthrough did not settle the fee");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev The owner finalizes at the vault itself, bypassing the helper: `settleFee` collects.
    function test_HelperFee_FilledElsewhere_OwnerVaultFinalize_SettleFeeCharges() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens,) = _createFeeOrder(collector);

        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);
        vm.prank(user);
        yzilp.finalizeRedeemOrder(orderId);
        assertEq(yzilp.balanceOf(collector), 0, "fee paid before settleFee");

        vm.prank(other);
        ilpHelper.settleFee(orderId);

        assertEq(yzilp.balanceOf(collector), feeTokens, "fee not paid by settleFee");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev Another vault filler settles the order below the owner's floor after a NAV drop. The
    /// helper refuses to pay that order out; the owner can still finalize it directly at the vault,
    /// and the escrowed fee then settles to the recipient.
    function test_FilledElsewhereBelowFloor_HelperFinalizeReverts_OwnerFinalizesAtVault() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens,) = _createFeeOrder(collector);

        _reportIlpPool(yzilp.poolSize() / 2);
        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);
        uint256 settled = yzilp.getRedeemOrder(orderId).assets;
        uint256 floor = ilpHelper.orderMinAssetsOut(orderId);
        assertLt(settled, floor, "setup: not below floor");

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.MinAssetsOutNotMet.selector, settled, floor));
        ilpHelper.finalizeRedeemOrder(orderId);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Filled), "order moved");

        uint256 userAssetsBefore = asset.balanceOf(user);
        vm.prank(user);
        yzilp.finalizeRedeemOrder(orderId);
        assertEq(asset.balanceOf(user), userAssetsBefore + settled, "owner not paid at the vault");

        ilpHelper.settleFee(orderId);
        assertEq(yzilp.balanceOf(collector), feeTokens, "fee not settled after owner finalize");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow not released");
    }

    /// @dev The floor check applies only to Filled orders: finalizing a Pending order still fails
    /// with the vault's own error, not a misleading floor error.
    function test_FinalizePassthrough_PendingOrder_VaultErrorUnchanged() public {
        (uint256 orderId,,,) = _createFeeOrder(makeAddr("collector"));
        vm.expectRevert();
        ilpHelper.finalizeRedeemOrder(orderId);
        try ilpHelper.finalizeRedeemOrder(orderId) {}
        catch (bytes memory err) {
            assertTrue(
                bytes4(err) != YuzuRedeemOrderHelper.MinAssetsOutNotMet.selector, "floor error on a pending order"
            );
        }
    }

    /// @dev (g) `settleFee` refuses a Pending order and a Filled-but-not-finalized order (the payout
    /// may still fail), settles once Finalized, and a second call is then a no-op.
    function test_HelperFee_SettleFee_RevertsWhilePendingOrFilled_SecondCallNoop() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens,) = _createFeeOrder(collector);

        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.FeeNotSettleable.selector, orderId));
        ilpHelper.settleFee(orderId);
        assertEq(ilpHelper.orderFeeTokens(orderId), feeTokens, "pending order lost its fee record");

        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Filled));

        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.FeeNotSettleable.selector, orderId));
        ilpHelper.settleFee(orderId);
        assertEq(ilpHelper.orderFeeTokens(orderId), feeTokens, "filled order lost its fee record");
        assertEq(yzilp.balanceOf(collector), 0, "fee paid before finalize");

        vm.prank(user);
        yzilp.finalizeRedeemOrder(orderId);
        ilpHelper.settleFee(orderId);
        assertEq(yzilp.balanceOf(collector), feeTokens, "fee not paid once finalized");

        vm.recordLogs();
        ilpHelper.settleFee(orderId);
        assertEq(vm.getRecordedLogs().length, 0, "second settleFee emitted events");
        assertEq(yzilp.balanceOf(collector), feeTokens, "second settleFee moved shares");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total drifted");
    }

    /// @dev (h) Switching the fee off between creation and fill: the fill succeeds and the owner is
    /// refunded the escrowed fee instead of the recipient being paid.
    function test_HelperFee_SwitchedOffBeforeFill_OwnerRefunded() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens, uint256 expected) = _createFeeOrder(collector);

        vm.prank(admin);
        ilpHelper.setFee(0, address(0));

        vm.expectEmit(true, true, false, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.RefundedFee(orderId, user, feeTokens);
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expected + 5e6, block.timestamp + 1 days);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        assertEq(yzilp.balanceOf(collector), 0, "waived fee was still paid");
        assertEq(yzilp.balanceOf(user), feeTokens, "owner was not refunded");
        assertEq(ilpHelper.orderFeeTokens(orderId), 0, "fee record not cleared");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev A rate change applies to new orders only: the fee amount is fixed at creation, so a rate
    /// zeroed before the fill (recipient left set) still pays the recipient.
    function test_HelperFee_RateZeroedBeforeFill_StillChargedToRecipient() public {
        address collector = makeAddr("collector");
        (uint256 orderId,, uint256 feeTokens, uint256 expected) = _createFeeOrder(collector);

        vm.prank(admin);
        ilpHelper.setFee(0, collector);

        vm.expectEmit(true, true, true, true, address(ilpHelper));
        emit IYuzuRedeemOrderHelper.ChargedFee(orderId, user, collector, feeTokens);
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expected + 5e6, block.timestamp + 1 days);

        assertEq(yzilp.balanceOf(collector), feeTokens, "recorded fee not paid to the recipient");
        assertEq(yzilp.balanceOf(user), 0, "owner should not be refunded");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "escrow total not cleared");
    }

    /// @dev Fees sent to the vault proxy are unrecoverable; to the helper itself, admin-rescuable.
    function test_SetFee_RevertsForVaultOrSelfRecipient() public {
        vm.startPrank(admin);
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidReceiver.selector);
        ilpHelper.setFee(10, address(yzilp));
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidReceiver.selector);
        ilpHelper.setFee(10, address(ilpHelper));
        vm.stopPrank();
    }

    /// @dev (i) `rescueTokens` can never take escrowed vault shares, but can take a donation above
    /// the escrow.
    function test_HelperFee_RescueTokens_ExcludesEscrow_AllowsDonation() public {
        address collector = makeAddr("collector");
        (,, uint256 feeTokens,) = _createFeeOrder(collector);

        vm.prank(other);
        uint256 donation = yzilp.deposit(10e6, other);
        vm.prank(other);
        yzilp.transfer(address(ilpHelper), donation);
        assertEq(yzilp.balanceOf(address(ilpHelper)), feeTokens + donation, "test setup: donation did not land");

        vm.startPrank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.RescueExceedsFreeBalance.selector, donation + 1, donation)
        );
        ilpHelper.rescueTokens(address(yzilp), treasury, donation + 1);

        ilpHelper.rescueTokens(address(yzilp), treasury, donation);
        vm.stopPrank();

        assertEq(yzilp.balanceOf(treasury), donation, "donation not recovered");
        assertEq(yzilp.balanceOf(address(ilpHelper)), feeTokens, "escrow disturbed");
        assertEq(ilpHelper.totalEscrowedFeeShares(), feeTokens, "escrow total disturbed");
    }

    /// @dev Dust: the fee rounds down, so it never exceeds `feeBps` of `tokens`. 99 shares at 100
    /// bps (1%) is 0.99 shares, i.e. nothing; 100 shares is exactly 1.
    function test_HelperFee_Dust_RoundsDownNeverAboveCap() public {
        address collector = makeAddr("collector");
        uint16 cap = ilpHelper.MAX_FEE_BPS();
        vm.prank(admin);
        ilpHelper.setFee(cap, collector);
        vm.prank(user);
        yzilp.deposit(100e6, user);

        vm.prank(user);
        uint256 dustOrder = ilpHelper.createRedeemOrderWithMaxFee(99, user, 1e6, 100, 1);
        assertEq(ilpHelper.orderFeeTokens(dustOrder), 0, "fee on 99 tokens at 100 bps must round to 0");
        assertEq(yzilp.getRedeemOrder(dustOrder).tokens, 99, "dust order should carry the full amount");

        vm.prank(user);
        uint256 hundredOrder = ilpHelper.createRedeemOrderWithMaxFee(100, user, 1e6, 100, 1);
        assertEq(ilpHelper.orderFeeTokens(hundredOrder), 1, "fee on 100 tokens at 100 bps is exactly 1");
        assertEq(yzilp.getRedeemOrder(hundredOrder).tokens, 99, "order should be net of the 1-share fee");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 1, "only the 1-share fee is escrowed");
    }

    /// @dev The caller's cap on the helper fee: if the admin raises the rate above it before the
    /// order is created, creation reverts and nothing is created or moved.
    function test_HelperFee_RaisedAboveCallerCap_CreateReverts() public {
        address collector = makeAddr("collector");
        vm.prank(admin);
        ilpHelper.setFee(30, collector);
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        vm.prank(admin);
        ilpHelper.setFee(100, collector);

        uint256 orderCountBefore = yzilp.orderCount();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.HelperFeeAboveMax.selector, 100, 30));
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 30, 1);

        assertEq(yzilp.orderCount(), orderCountBefore, "an order was created despite the revert");
        assertEq(yzilp.balanceOf(user), shares, "owner shares moved despite the revert");
        assertEq(yzilp.balanceOf(collector), 0, "fee paid despite the revert");

        // At the rate the caller agreed to, the same call goes through.
        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending));
    }

    function test_HelperFee_CapAndRecipientGuards() public {
        uint16 cap = ilpHelper.MAX_FEE_BPS();
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.FeeTooHigh.selector, cap + 1, cap));
        ilpHelper.setFee(cap + 1, makeAddr("collector"));
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidZeroAddress.selector);
        ilpHelper.setFee(10, address(0));
        ilpHelper.setFee(0, address(0));
        vm.stopPrank();
    }

    function test_RescueTokens_RequiresAdminRole() public {
        asset.mint(address(ilpHelper), 5);

        bytes32 adminRole = ilpHelper.ADMIN_ROLE();
        vm.prank(other);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, other, adminRole)
        );
        ilpHelper.rescueTokens(address(asset), other, 5);

        vm.prank(admin);
        ilpHelper.rescueTokens(address(asset), admin, 5);
        assertEq(asset.balanceOf(address(ilpHelper)), 0);
    }

    function test_Constructor_Revert_AssetMismatch() public {
        address wrongAsset = address(_newAsset());
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.AssetMismatch.selector, wrongAsset, address(asset))
        );
        new YuzuRedeemOrderHelper(address(yzilp), wrongAsset, admin, admin);
    }

    function test_Constructor_Revert_ZeroAddress() public {
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidZeroAddress.selector);
        new YuzuRedeemOrderHelper(address(0), address(asset), admin, admin);
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidZeroAddress.selector);
        new YuzuRedeemOrderHelper(address(yzilp), address(asset), admin, address(0));
    }

    // --- gap-fill: F1, previewRedeemOrder never appears in the settlement path -----------------

    /// @dev Phase-04 requirement: inspect via a mock vault that reverts on `previewRedeemOrder`,
    /// and confirm `fillAndFinalizeRedeemOrder` still succeeds. If the settlement path ever called
    /// it, this whole test would revert instead of asserting a finalized order.
    function test_F1_SettlementNeverCallsPreviewRedeemOrder() public {
        RevertingPreviewVault mockVault = new RevertingPreviewVault(address(asset));
        YuzuRedeemOrderHelper mockHelper = new YuzuRedeemOrderHelper(address(mockVault), address(asset), admin, admin);

        bytes32 fillerRole = mockHelper.FILLER_ROLE();
        vm.startPrank(admin);
        mockHelper.grantRole(fillerRole, helperFiller);
        mockHelper.setWhitelistEnabled(false);
        mockHelper.grantRole(mockHelper.LIMIT_MANAGER_ROLE(), admin);
        mockHelper.setLimits(type(uint256).max, type(uint256).max, type(uint256).max);
        vm.stopPrank();
        vm.prank(helperFiller);
        asset.approve(address(mockHelper), type(uint256).max);

        vm.prank(user);
        uint256 orderId = mockHelper.createRedeemOrderWithMaxFee(100e6, user, 1e6, 100, 1);

        uint256 receiverBalBefore = asset.balanceOf(user);
        vm.prank(helperFiller);
        mockHelper.fillAndFinalizeRedeemOrder(orderId, 100e6, block.timestamp + 1 days);

        assertEq(uint256(mockVault.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        assertEq(asset.balanceOf(user), receiverBalBefore + 100e6, "receiver not paid by the mock's settlement");
    }

    // --- restatement gate ------------------------------------------------------------------------

    /// @dev The two V3 families expose their restatement freeze through different predicates, and
    /// `YuzuILPV2.canRedeem` is hardcoded `false` — ILP has no instant redeem path at all. A gate
    /// written as "reuse the instant-path predicate" would therefore pass every yzUSD test and
    /// brick every yzILP fill. This pins the probe's classification and, more importantly, pins
    /// that a normal ILP fill still succeeds while `canRedeem` is false.
    function test_Restatement_ProbeSelectsFamilyPredicate() public {
        assertTrue(ilpHelper.vaultExposesPoolUpdateFlag(), "ILP vault should be classified by isUpdatingPool()");
        assertFalse(usdHelper.vaultExposesPoolUpdateFlag(), "USD vault should fall back to canRedeem");
        assertFalse(IYuzuProtoV2(address(yzilp)).canRedeem(user), "ILP canRedeem is expected to be hardcoded false");

        _happyPath(IYuzuProto(address(yzilp)), ilpHelper);
    }

    function test_Restatement_ILP_BlocksCreateAndFillDuringPoolUpdate() public {
        (uint256 orderId, uint256 expectedAssets) =
            _createOrderAndSnapshotExpected(IYuzuProto(address(yzilp)), ilpHelper, 100e6);

        vm.prank(admin);
        yzilp.startPoolUpdate();

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, user));
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, other));
        ilpHelper.createRedeemOrderWithMaxFee(1e6, other, 1e6, 100, 1);

        vm.prank(admin);
        yzilp.endPoolUpdate();

        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    function test_Restatement_USD_BlocksCreateAndFillDuringNavUpdate() public {
        vm.prank(admin);
        yzusd.grantRole(NAV_MANAGER_ROLE, navManager);

        (uint256 orderId, uint256 expectedAssets) =
            _createOrderAndSnapshotExpected(IYuzuProto(address(yzusd)), usdHelper, 100e6);

        vm.prank(navManager);
        yzusd.setNavUpdateInProgress(true);

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, user));
        usdHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, other));
        usdHelper.createRedeemOrderWithMaxFee(1e6, other, 1e6, 100, 1);

        vm.prank(navManager);
        yzusd.setNavUpdateInProgress(false);

        vm.prank(helperFiller);
        usdHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);
        assertEq(uint256(yzusd.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    // --- owner price floor on the base path --------------------------------------------------------

    function test_MinAssetsOut_BasePath_RevertsOnShortfall() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        uint256 expectedAssets = yzilp.previewRedeemOrder(shares);

        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, expectedAssets);
        assertEq(ilpHelper.orderMinAssetsOut(orderId), expectedAssets, "floor not recorded at creation");

        _reportIlpPool(yzilp.poolSize() / 2);
        uint256 settledAfterMarkdown = yzilp.previewRedeemOrder(shares);
        assertLt(settledAfterMarkdown, expectedAssets, "test setup: markdown did not create a shortfall");

        uint256 sharesBefore = yzilp.balanceOf(user);
        uint256 fillerBalBefore = asset.balanceOf(helperFiller);

        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(
                YuzuRedeemOrderHelper.MinAssetsOutNotMet.selector, settledAfterMarkdown, expectedAssets
            )
        );
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

        assertEq(yzilp.balanceOf(user), sharesBefore, "shares consumed despite revert");
        assertEq(asset.balanceOf(helperFiller), fillerBalBefore, "filler asset moved despite revert");
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending), "order left non-pending");
    }

    function test_MinAssetsOut_BasePath_PassesWhenFloorMet() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        uint256 expectedAssets = yzilp.previewRedeemOrder(shares);

        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, expectedAssets);

        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    function test_Create_Revert_ZeroMinAssetsOut() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        vm.prank(user);
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidMinAssetsOut.selector);
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 0);
    }

    // --- self-referential receiver ------------------------------------------------------------------

    /// @dev A helper-as-receiver order credits the helper on finalize, so `exitBalance ==
    /// entryBalance` can never hold and the order's only fill path is bricked for good. Rejected at
    /// creation instead.
    function test_Create_Revert_ReceiverIsHelper() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        vm.prank(user);
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidReceiver.selector);
        ilpHelper.createRedeemOrderWithMaxFee(shares, address(ilpHelper), 1e6, 100, 1);
    }

    /// @dev The vault proxy cannot be a receiver either: assets paid there are unrecoverable.
    function test_Create_Revert_ReceiverIsVault() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);

        vm.prank(user);
        vm.expectRevert(YuzuRedeemOrderHelper.InvalidReceiver.selector);
        ilpHelper.createRedeemOrderWithMaxFee(shares, address(yzilp), 1e6, 100, 1);
        assertEq(yzilp.balanceOf(user), shares, "shares moved despite the revert");
    }

    // --- yzUSD-side coverage of the same two guards -------------------------------------------------

    /// @dev Applies a NAV markdown the way ops does: stage the update, write the NAV, clear the flag.
    function _markdownNav(uint256 newNav) internal {
        vm.prank(admin);
        yzusd.grantRole(NAV_MANAGER_ROLE, navManager);
        vm.prank(navManager);
        yzusd.setNavUpdateInProgress(true);
        vm.prank(navManager);
        yzusd.setNav(newNav);
        vm.prank(navManager);
        yzusd.setNavUpdateInProgress(false);
    }

    /// @dev The floor is family-agnostic, but the two families move price through different
    /// machinery — yzILP restates `poolSize`, yzUSD writes NAV. Both must trip the same guard.
    function test_MinAssetsOut_USD_RevertsOnNavMarkdown() public {
        vm.prank(user);
        uint256 shares = yzusd.deposit(100e6, user);
        uint256 expectedAssets = yzusd.previewRedeemOrder(shares);

        vm.prank(user);
        uint256 orderId = usdHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, expectedAssets);

        _markdownNav(9e17); // -10%, exactly the step cap
        uint256 settledAfterMarkdown = yzusd.previewRedeemOrder(shares);
        assertLt(settledAfterMarkdown, expectedAssets, "test setup: markdown did not create a shortfall");

        uint256 sharesBefore = yzusd.balanceOf(user);
        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(
                YuzuRedeemOrderHelper.MinAssetsOutNotMet.selector, settledAfterMarkdown, expectedAssets
            )
        );
        usdHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);

        assertEq(yzusd.balanceOf(user), sharesBefore, "shares consumed despite revert");
        assertEq(uint256(yzusd.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending), "order left non-pending");
    }

    /// @dev The restatement gate must never close the recovery door. `finalizeRedeemOrder` is the
    /// permissionless passthrough that rescues an order already filled elsewhere; gating it would
    /// strand the filler's assets in the vault for the duration of every restatement.
    function test_Restatement_DoesNotBlockPermissionlessFinalize() public {
        vm.prank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        uint256 expectedAssets = yzilp.previewRedeemOrder(shares);

        vm.prank(user);
        uint256 orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);

        // Filled directly on the vault by the ordinary vault-level filler, leaving it Filled.
        deal(address(asset), filler, expectedAssets + 10e6);
        vm.startPrank(filler);
        asset.approve(address(yzilp), type(uint256).max);
        yzilp.fillRedeemOrder(orderId);
        vm.stopPrank();
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Filled));

        vm.prank(admin);
        yzilp.startPoolUpdate();

        // Creation and settlement are closed...
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, other));
        ilpHelper.createRedeemOrderWithMaxFee(1e6, other, 1e6, 100, 1);

        // ...but the recovery path is not, and pays the user at the price already settled.
        uint256 balBefore = asset.balanceOf(user);
        uint256 settled = yzilp.getRedeemOrder(orderId).assets;
        ilpHelper.finalizeRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
        assertEq(asset.balanceOf(user), balBefore + settled, "recovery path did not pay the user");
    }

    /// @dev Role gating is covered separately; this covers the recovery itself. A donation is
    /// deliberately tolerated by settlement rather than rejected, so the only way it ever leaves is
    /// this function — and it must not disturb an unrelated order settling around it.
    function test_RescueTokens_RecoversDonatedAsset() public {
        vm.prank(other);
        asset.transfer(address(ilpHelper), 1_234e6);
        assertEq(asset.balanceOf(address(ilpHelper)), 1_234e6, "donation did not land");

        // A normal settlement still works on top of the donation and leaves it untouched.
        (uint256 orderId, uint256 expectedAssets) =
            _createOrderAndSnapshotExpected(IYuzuProto(address(yzilp)), ilpHelper, 100e6);
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 10e6, block.timestamp + 1 days);
        assertEq(asset.balanceOf(address(ilpHelper)), 1_234e6, "settlement disturbed the donation");

        uint256 treasuryBefore = asset.balanceOf(treasury);
        vm.prank(admin);
        ilpHelper.rescueTokens(address(asset), treasury, 1_234e6);

        assertEq(asset.balanceOf(treasury), treasuryBefore + 1_234e6, "donation not recovered");
        assertEq(asset.balanceOf(address(ilpHelper)), 0, "helper still holds the donation");
    }

    // --- helper whitelist ----------------------------------------------------------------------

    /// @dev Deposits `assets` for `who` and creates a helper order for the full share balance.
    function _createOrder(address who, uint256 assets) internal returns (uint256 orderId, uint256 expectedAssets) {
        vm.startPrank(who);
        uint256 shares = yzilp.deposit(assets, who);
        yzilp.approve(address(ilpHelper), shares);
        orderId = ilpHelper.createRedeemOrderWithMaxFee(shares, who, 1e6, 100, 1);
        vm.stopPrank();
        expectedAssets = yzilp.previewRedeemOrder(shares);
    }

    function _fill(uint256 orderId, uint256 expectedAssets) internal {
        vm.prank(helperFiller);
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets, block.timestamp + 1 days);
    }

    function _whitelist(address account, bool allowed) internal {
        address[] memory accounts = new address[](1);
        accounts[0] = account;
        vm.startPrank(admin);
        ilpHelper.grantRole(ilpHelper.WHITELIST_MANAGER_ROLE(), admin);
        ilpHelper.setWhitelisted(accounts, allowed);
        vm.stopPrank();
    }

    function test_Whitelist_OnByDefault() public {
        YuzuRedeemOrderHelper fresh = new YuzuRedeemOrderHelper(address(yzilp), address(asset), admin, admin);
        assertTrue(fresh.whitelistEnabled());

        vm.startPrank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        yzilp.approve(address(fresh), shares);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.NotWhitelisted.selector, user));
        fresh.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        vm.stopPrank();
    }

    /// @dev Only listed owners create; delisting a partner also stops the fill of their pending
    /// order, which stays Pending rather than being lost.
    function test_Whitelist_GatesCreateAndFill() public {
        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(true);
        _whitelist(user, true);

        vm.startPrank(other);
        uint256 otherShares = yzilp.deposit(100e6, other);
        yzilp.approve(address(ilpHelper), otherShares);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.NotWhitelisted.selector, other));
        ilpHelper.createRedeemOrderWithMaxFee(otherShares, other, 1e6, 100, 1);
        vm.stopPrank();

        (uint256 orderId, uint256 expectedAssets) = _createOrder(user, 100e6);
        _whitelist(user, false);

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.NotWhitelisted.selector, user));
        ilpHelper.fillAndFinalizeRedeemOrder(orderId, expectedAssets, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending));

        _whitelist(user, true);
        _fill(orderId, expectedAssets);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Finalized));
    }

    /// @dev The helper list adds to the vault's own `REDEEMER_ROLE` list; it never replaces it.
    function test_Whitelist_VaultRedeemerListStillApplies() public {
        vm.startPrank(admin);
        ilpHelper.setWhitelistEnabled(true);
        yzilp.grantRole(RESTRICTION_MANAGER_ROLE, admin);
        yzilp.setIsRedeemRestricted(true);
        vm.stopPrank();
        _whitelist(user, true);

        vm.startPrank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        vm.expectRevert(
            abi.encodeWithSelector(IYuzuOrderBookDefinitions.ExceededMaxRedeemOrder.selector, user, shares, 0)
        );
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        vm.stopPrank();
    }

    function test_Whitelist_SetterAccess() public {
        address[] memory accounts = new address[](1);
        accounts[0] = other;
        vm.startPrank(other);
        vm.expectRevert();
        ilpHelper.setWhitelisted(accounts, true);
        vm.expectRevert();
        ilpHelper.setWhitelistEnabled(false);
        vm.stopPrank();

        // The list manager cannot open the helper; only ADMIN_ROLE can.
        bytes32 listRole = ilpHelper.WHITELIST_MANAGER_ROLE();
        vm.prank(admin);
        ilpHelper.grantRole(listRole, other);
        vm.startPrank(other);
        ilpHelper.setWhitelisted(accounts, true);
        vm.expectRevert();
        ilpHelper.setWhitelistEnabled(false);
        vm.stopPrank();
        assertTrue(ilpHelper.isWhitelisted(other));
    }

    /// @dev Switching the gate never edits the list: off admits anyone the vault allows, and on
    /// again restores exactly the partners listed before.
    function test_Whitelist_ToggleKeepsList() public {
        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(true);
        _whitelist(user, true);

        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(false);
        (uint256 otherOrder, uint256 otherAssets) = _createOrder(other, 100e6);

        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(true);
        assertTrue(ilpHelper.isWhitelisted(user), "list lost on toggle");
        assertFalse(ilpHelper.isWhitelisted(other), "toggle-off admission leaked into the list");
        _createOrder(user, 100e6);

        // An order created while open is gated again once the list is back on.
        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.NotWhitelisted.selector, other));
        ilpHelper.fillAndFinalizeRedeemOrder(otherOrder, otherAssets, block.timestamp + 1 days);
    }

    /// @dev Delisting stops helper fills but never traps funds: the owner's own vault cancel after
    /// `dueTime` plus {settleFee}, and the admin's `cancelOwnRedeemOrder`, both return every share,
    /// the escrowed helper fee included.
    function test_Whitelist_DelistedOwnerRecoversShares() public {
        address collector = makeAddr("collector");
        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(true);
        _whitelist(user, true);

        (uint256 orderId, uint256 shares,,) = _createFeeOrder(collector);
        _whitelist(user, false);

        vm.warp(block.timestamp + yzilp.fillWindow());
        vm.prank(user);
        yzilp.cancelRedeemOrder(orderId);
        vm.prank(other);
        ilpHelper.settleFee(orderId);
        assertEq(yzilp.balanceOf(user), shares, "owner vault cancel did not return every share");

        _whitelist(user, true);
        vm.prank(user);
        uint256 secondOrder = ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        _whitelist(user, false);

        vm.prank(admin);
        ilpHelper.cancelOwnRedeemOrder(secondOrder);
        assertEq(yzilp.balanceOf(user), shares, "admin cancel did not return every share");
        assertEq(ilpHelper.totalEscrowedFeeShares(), 0, "fee left in escrow");
    }

    /// @dev An order already filled (by another vault filler) is paid out through the helper's
    /// permissionless finalize even after its owner is delisted: the payout is never gated.
    function test_Whitelist_DelistedOwnerFilledOrderStillFinalizes() public {
        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(true);
        _whitelist(user, true);
        (uint256 orderId,) = _createOrder(user, 100e6);

        asset.mint(filler, 1_000e6);
        _approve(filler, address(yzilp));
        vm.prank(filler);
        yzilp.fillRedeemOrder(orderId);
        _whitelist(user, false);

        uint256 balBefore = asset.balanceOf(user);
        uint256 settled = yzilp.getRedeemOrder(orderId).assets;
        vm.prank(other);
        ilpHelper.finalizeRedeemOrder(orderId);
        assertEq(asset.balanceOf(user), balBefore + settled, "delisted owner not paid");
    }

    /// @dev The gate truth table: creation succeeds exactly when the list is off or the owner is on it.
    function testFuzz_Whitelist_CreateGate(bool enabled, bool listed) public {
        vm.prank(admin);
        ilpHelper.setWhitelistEnabled(enabled);
        _whitelist(user, listed);

        vm.startPrank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        yzilp.approve(address(ilpHelper), shares);
        if (enabled && !listed) {
            vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.NotWhitelisted.selector, user));
        }
        ilpHelper.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        vm.stopPrank();
    }

    // --- outflow limits ------------------------------------------------------------------------

    function _setLimits(uint256 txCap_, uint256 accountLimit_, uint256 totalLimit_) internal {
        vm.prank(admin);
        ilpHelper.setLimits(txCap_, accountLimit_, totalLimit_);
    }

    function test_Limits_FreshHelperFailsClosed() public {
        YuzuRedeemOrderHelper fresh = new YuzuRedeemOrderHelper(address(yzilp), address(asset), admin, admin);
        bytes32 fillerRole = fresh.FILLER_ROLE();
        bytes32 listRole = fresh.WHITELIST_MANAGER_ROLE();
        address[] memory partners = new address[](1);
        partners[0] = user;
        vm.startPrank(admin);
        yzilp.grantRole(ORDER_FILLER_ROLE, address(fresh));
        fresh.grantRole(fillerRole, helperFiller);
        fresh.grantRole(listRole, admin);
        fresh.setWhitelisted(partners, true);
        vm.stopPrank();
        vm.prank(helperFiller);
        asset.approve(address(fresh), type(uint256).max);

        vm.startPrank(user);
        uint256 shares = yzilp.deposit(100e6, user);
        yzilp.approve(address(fresh), shares);
        uint256 orderId = fresh.createRedeemOrderWithMaxFee(shares, user, 1e6, 100, 1);
        vm.stopPrank();
        uint256 expectedAssets = yzilp.previewRedeemOrder(shares);

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.AboveTxCap.selector, expectedAssets, 0));
        fresh.fillAndFinalizeRedeemOrder(orderId, expectedAssets, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending));
    }

    function test_Limits_TxCapBlocksLargeFillOnly() public {
        (uint256 small, uint256 smallAssets) = _createOrder(user, 100e6);
        (uint256 large, uint256 largeAssets) = _createOrder(user, 300e6);
        _setLimits(smallAssets, type(uint256).max, type(uint256).max);

        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.AboveTxCap.selector, largeAssets, smallAssets));
        ilpHelper.fillAndFinalizeRedeemOrder(large, largeAssets, block.timestamp + 1 days);
        assertEq(uint256(yzilp.getRedeemOrder(large).status), uint256(OrderStatus.Pending), "large order lost");

        _fill(small, smallAssets);
        assertEq(uint256(yzilp.getRedeemOrder(small).status), uint256(OrderStatus.Finalized));
    }

    /// @dev One owner exhausting its limit must not touch another owner's, and the limit refills
    /// linearly: half after 12h, all of it after 24h.
    function test_Limits_AccountLimitIsPerOwnerAndRefills() public {
        (uint256 a1, uint256 assets1) = _createOrder(user, 100e6);
        (uint256 a2, uint256 assets2) = _createOrder(user, 100e6);
        (uint256 b1, uint256 assetsB) = _createOrder(other, 100e6);
        uint256 limit = assets1 + assets2 / 2;
        _setLimits(type(uint256).max, limit, type(uint256).max);

        _fill(a1, assets1);
        assertEq(ilpHelper.remainingAccountLimit(user), limit - assets1);

        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.AccountLimitExceeded.selector, user, assets2, limit - assets1)
        );
        ilpHelper.fillAndFinalizeRedeemOrder(a2, assets2, block.timestamp + 1 days);

        _fill(b1, assetsB);
        assertEq(ilpHelper.remainingAccountLimit(other), limit - assetsB, "other owner's limit was shared");

        // Absolute targets: under via_ir, `block.timestamp` after a warp can read the cached value.
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 12 hours);
        assertEq(ilpHelper.remainingAccountLimit(user), limit - assets1 + limit / 2, "not half refilled");
        _fill(a2, assets2);

        vm.warp(t0 + 36 hours);
        assertEq(ilpHelper.remainingAccountLimit(user), limit, "not fully refilled after a quiet window");
    }

    function test_Limits_TotalLimitAcrossOwners() public {
        (uint256 a1, uint256 assetsA) = _createOrder(user, 100e6);
        (uint256 b1, uint256 assetsB) = _createOrder(other, 100e6);
        uint256 limit = assetsA + assetsB - 1;
        _setLimits(type(uint256).max, type(uint256).max, limit);

        _fill(a1, assetsA);
        vm.prank(helperFiller);
        vm.expectRevert(
            abi.encodeWithSelector(YuzuRedeemOrderHelper.TotalLimitExceeded.selector, assetsB, limit - assetsA)
        );
        ilpHelper.fillAndFinalizeRedeemOrder(b1, assetsB, block.timestamp + 1 days);

        vm.warp(block.timestamp + 1 hours);
        _fill(b1, assetsB);
        assertEq(uint256(yzilp.getRedeemOrder(b1).status), uint256(OrderStatus.Finalized));
    }

    /// @dev Lowering a limit under recorded usage leaves no capacity until usage decays at the new
    /// rate; it never underflows or reopens early.
    function test_Limits_LoweredBelowUsageBlocksUntilDecay() public {
        (uint256 a1, uint256 assets1) = _createOrder(user, 100e6);
        (uint256 a2, uint256 assets2) = _createOrder(user, 10e6);
        _setLimits(type(uint256).max, type(uint256).max, 200e6);
        _fill(a1, assets1);

        _setLimits(type(uint256).max, type(uint256).max, 40e6);
        assertEq(ilpHelper.remainingTotalLimit(), 0);

        // After 18h, 30e6 of the ~100e6 used has decayed at the new rate: still nothing left.
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 18 hours);
        assertEq(ilpHelper.remainingTotalLimit(), 0);
        vm.prank(helperFiller);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.TotalLimitExceeded.selector, assets2, 0));
        ilpHelper.fillAndFinalizeRedeemOrder(a2, assets2, block.timestamp + 1 days);

        vm.warp(t0 + 24 hours);
        assertEq(ilpHelper.remainingTotalLimit(), 40e6);
        _fill(a2, assets2);
    }

    function test_Limits_SetLimitsAccessAndBounds() public {
        vm.prank(other);
        vm.expectRevert();
        ilpHelper.setLimits(1, 1, 1);

        uint256 tooLarge = uint256(type(uint192).max) + 1;
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.InvalidLimit.selector, tooLarge));
        ilpHelper.setLimits(1, tooLarge, 1);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.InvalidLimit.selector, tooLarge));
        ilpHelper.setLimits(1, 1, tooLarge);
        ilpHelper.setLimits(type(uint256).max, type(uint192).max, type(uint256).max);
        vm.stopPrank();
    }

    // --- cancel role ---------------------------------------------------------------------------

    /// @dev The cancel power is its own role: `ADMIN_ROLE` alone cannot cancel, and a holder of
    /// only `CANCEL_MANAGER_ROLE` can, with every share returned to the owner.
    function test_CancelRole_SeparateFromAdmin() public {
        (uint256 orderId,) = _createOrder(user, 100e6);
        uint256 sharesAfterCreate = yzilp.balanceOf(user);
        bytes32 cancelRole = ilpHelper.CANCEL_MANAGER_ROLE();
        address canceller = makeAddr("canceller");

        vm.prank(admin);
        ilpHelper.revokeRole(cancelRole, admin);
        assertTrue(ilpHelper.hasRole(ilpHelper.ADMIN_ROLE(), admin));
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, admin, cancelRole)
        );
        ilpHelper.cancelOwnRedeemOrder(orderId);

        vm.prank(admin);
        ilpHelper.grantRole(cancelRole, canceller);
        assertFalse(ilpHelper.hasRole(ilpHelper.ADMIN_ROLE(), canceller));
        vm.prank(canceller);
        ilpHelper.cancelOwnRedeemOrder(orderId);

        assertEq(uint256(yzilp.getRedeemOrder(orderId).status), uint256(OrderStatus.Cancelled));
        assertGt(yzilp.balanceOf(user), sharesAfterCreate, "shares not returned to the owner");
    }
}
