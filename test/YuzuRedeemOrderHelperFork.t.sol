// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Order, OrderStatus} from "../src/interfaces/proto/IYuzuOrderBookDefinitions.sol";
import {IYuzuProto} from "../src/interfaces/proto/IYuzuProto.sol";
import {IYuzuILPV2} from "../src/interfaces/IYuzuILP.sol";
import {YuzuRedeemOrderHelper} from "../src/helpers/YuzuRedeemOrderHelper.sol";
import {ADMIN_ROLE, FEE_MANAGER_ROLE, ORDER_FILLER_ROLE} from "./helpers/TestRoles.sol";

/// @dev Live yzCash (Ethereum, ILP V3), `RPC_URL`-gated and block-pinned -- mirrors the repo's
/// fork idiom (`test/upgrade/PSMV2.t.sol:20`). Skips cleanly with no fork key so CI without one
/// still passes. Target state from
/// `plans/reports/verification-260904-yzilpv3-fleet-post-upgrade.md`.
contract YuzuRedeemOrderHelperForkTest is Test {
    address internal constant YZCASH = 0x224e90591A2d63fb66E677D0561Ea4A6Ad1F098D;
    /// @dev A second live ILP V3 vault, used only by scenario 9: at the pinned block its pool
    /// update is staged on-chain, which no fixture can honestly reproduce.
    address internal constant YZUSDE = 0x246C6C4C4A4aB1ddd44E41a3535073e4B92Dc23d;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant EXISTING_ORDER_FILLER = 0x9D7c56AfeE66020816689469aEC4DB3623F78263;
    /// @dev yzCash's `DEFAULT_ADMIN_ROLE` holder at the pinned block -- the only address that can
    /// bootstrap `ADMIN_ROLE` for this test, since `ORDER_FILLER_ROLE`'s role-admin is `ADMIN_ROLE`
    /// (`src/proto/YuzuProto.sol:93`), not `DEFAULT_ADMIN_ROLE` itself.
    address internal constant YZCASH_DEFAULT_ADMIN = 0xD2160Ad387C592010650B3BFE14a5e1A17DC7E5e;
    /// @dev Ethereum head at the time the target-vault snapshot was verified (2026-09-04); a real,
    /// already-mined block -- never `latest`. Overridable for a deliberate re-verification.
    uint256 internal constant PINNED_BLOCK = 25_902_447;

    IYuzuProto internal vault;
    IERC20 internal shareToken;
    IERC20 internal asset;
    YuzuRedeemOrderHelper internal helper;

    address internal admin = makeAddr("forkAdmin");
    address internal helperFiller = makeAddr("forkHelperFiller");

    /// @dev Forks, deploys the helper and wires its roles exactly as ops would. Returns `false`
    /// (after calling `vm.skip(true)`) when no fork key is configured.
    function _setUpFork() internal returns (bool) {
        string memory rpcUrl = vm.envOr("RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            vm.skip(true);
            return false;
        }
        uint256 forkBlock = vm.envOr("YZCASH_FORK_BLOCK", PINNED_BLOCK);
        vm.createSelectFork(rpcUrl, forkBlock);

        vault = IYuzuProto(YZCASH);
        shareToken = IERC20(YZCASH);
        asset = IERC20(USDC);

        vm.prank(YZCASH_DEFAULT_ADMIN);
        IAccessControl(YZCASH).grantRole(ADMIN_ROLE, address(this));

        helper = new YuzuRedeemOrderHelper(YZCASH, USDC, admin, admin);
        IAccessControl(YZCASH).grantRole(ORDER_FILLER_ROLE, address(helper));

        bytes32 fillerRole = helper.FILLER_ROLE();
        vm.startPrank(admin);
        helper.grantRole(fillerRole, helperFiller);
        helper.setWhitelistEnabled(false);
        helper.grantRole(helper.LIMIT_MANAGER_ROLE(), admin);
        helper.grantRole(helper.CANCEL_MANAGER_ROLE(), admin);
        helper.setLimits(type(uint256).max, type(uint256).max, type(uint256).max);
        vm.stopPrank();

        return true;
    }

    function _fundAndDeposit(address who, uint256 assets) internal returns (uint256 shares) {
        deal(address(asset), who, assets);
        vm.prank(who);
        asset.approve(YZCASH, type(uint256).max);
        vm.prank(who);
        shares = vault.deposit(assets, who);
    }

    // --- 1. Deploy helper, prank admin to grant ORDER_FILLER_ROLE, run the happy path -----------

    function test_ForkScenario1_HappyPath_FillAndFinalize() public {
        if (!_setUpFork()) return;

        address forkUser = makeAddr("forkUser1");
        uint256 shares = _fundAndDeposit(forkUser, 10_000e6);

        vm.prank(forkUser);
        shareToken.approve(address(helper), type(uint256).max);

        uint256 expectedAssets = vault.previewRedeemOrder(shares);
        vm.prank(forkUser);
        uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, forkUser, 1_000_000, 100, 1);

        deal(address(asset), helperFiller, expectedAssets + 1_000e6);
        vm.prank(helperFiller);
        asset.approve(address(helper), type(uint256).max);

        // A third-party dust donation before the fill, live (F2): the helper must still settle
        // and return to this entry snapshot, never to an absolute zero.
        deal(address(asset), address(this), 1);
        asset.transfer(address(helper), 1);
        uint256 helperBalBefore = asset.balanceOf(address(helper));

        uint256 balBefore = asset.balanceOf(forkUser);
        vm.prank(helperFiller);
        helper.fillAndFinalizeRedeemOrder(orderId, expectedAssets + 1_000e6, block.timestamp + 1 days);

        Order memory order = vault.getRedeemOrder(orderId);
        assertEq(uint256(order.status), uint256(OrderStatus.Finalized), "order not finalized on live yzCash");
        assertEq(order.controller, address(helper), "controller drifted");
        assertEq(asset.balanceOf(forkUser), balBefore + order.assets, "user underpaid on live yzCash");
        assertEq(asset.balanceOf(address(helper)), helperBalBefore, "helper balance drifted from its entry snapshot");
    }

    // --- 2. Same, but with real accrued yield across a warp -------------------------------------

    function test_ForkScenario2_RealAccruedYield_SettlesCorrectly() public {
        if (!_setUpFork()) return;

        address forkUser = makeAddr("forkUser2");
        uint256 shares = _fundAndDeposit(forkUser, 10_000e6);

        vm.prank(forkUser);
        shareToken.approve(address(helper), type(uint256).max);

        vm.prank(forkUser);
        uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, forkUser, 1_000_000, 100, 1);

        // Warp inside the order's own fill window while yzCash's real linear accrual (159 ppm/day
        // at the verified snapshot) keeps moving NAV -- no local fixture can produce this drift.
        uint256 fillWindow = vault.fillWindow();
        vm.warp(block.timestamp + (fillWindow / 2));

        uint256 previewAtFillTime = vault.previewRedeemOrder(shares);
        deal(address(asset), helperFiller, previewAtFillTime + 1_000e6);
        vm.prank(helperFiller);
        asset.approve(address(helper), type(uint256).max);

        uint256 helperBalBefore = asset.balanceOf(address(helper));
        uint256 balBefore = asset.balanceOf(forkUser);
        vm.prank(helperFiller);
        helper.fillAndFinalizeRedeemOrder(orderId, previewAtFillTime + 1_000e6, block.timestamp + 1 days);

        Order memory order = vault.getRedeemOrder(orderId);
        assertEq(uint256(order.status), uint256(OrderStatus.Finalized), "order not finalized after accrual warp");
        assertEq(
            asset.balanceOf(forkUser), balBefore + order.assets, "receiver did not get the accrual-adjusted settlement"
        );
        assertEq(asset.balanceOf(address(helper)), helperBalBefore, "helper balance drifted from its entry snapshot");
    }

    // --- 3. Full fee-mutation matrix against live state ------------------------------------------

    function test_ForkScenario3_FeeMutationMatrix_LiveState() public {
        if (!_setUpFork()) return;

        IAccessControl(YZCASH).grantRole(FEE_MANAGER_ROLE, address(this));
        uint256 originalFee = vault.redeemOrderFeePpm();

        // Row 1: no fee change -- settles at the stamped fee, filler refunded the unused amount.
        {
            address u = makeAddr("forkUser3row1");
            uint256 shares = _fundAndDeposit(u, 5_000e6);
            vm.prank(u);
            shareToken.approve(address(helper), type(uint256).max);
            uint256 expected = vault.previewRedeemOrder(shares);

            vm.prank(u);
            uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, u, 1_000_000, 100, 1);
            deal(address(asset), helperFiller, expected + 1_000e6);
            vm.prank(helperFiller);
            asset.approve(address(helper), type(uint256).max);
            uint256 fillerBalBefore = asset.balanceOf(helperFiller);

            vm.prank(helperFiller);
            helper.fillAndFinalizeRedeemOrder(orderId, expected + 1_000e6, block.timestamp + 1 days);

            assertEq(vault.getRedeemOrder(orderId).assets, expected, "row1: mispriced on live state");
            assertEq(asset.balanceOf(helperFiller), fillerBalBefore - expected, "row1: refund wrong on live state");
        }

        // Row 2: fee raised after creation -- the broken (preview-at-fill) design would price this
        // differently; the fix settles at the stamped fee regardless.
        {
            address u = makeAddr("forkUser3row2");
            uint256 shares = _fundAndDeposit(u, 5_000e6);
            vm.prank(u);
            shareToken.approve(address(helper), type(uint256).max);
            uint256 expected = vault.previewRedeemOrder(shares);

            vm.prank(u);
            uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, u, 1_000_000, 100, 1);
            vault.setRedeemOrderFee(50_000); // 5%, raised from live fee

            deal(address(asset), helperFiller, expected + 1_000e6);
            vm.prank(helperFiller);
            asset.approve(address(helper), type(uint256).max);
            vm.prank(helperFiller);
            helper.fillAndFinalizeRedeemOrder(orderId, expected + 1_000e6, block.timestamp + 1 days);

            assertEq(vault.getRedeemOrder(orderId).assets, expected, "row2: fee raise altered live settlement");
            vault.setRedeemOrderFee(originalFee);
        }

        // Row 3: fee lowered after creation -- same property, opposite direction.
        {
            vault.setRedeemOrderFee(50_000);
            address u = makeAddr("forkUser3row3");
            uint256 shares = _fundAndDeposit(u, 5_000e6);
            vm.prank(u);
            shareToken.approve(address(helper), type(uint256).max);
            uint256 expected = vault.previewRedeemOrder(shares);

            vm.prank(u);
            uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, u, 1_000_000, 100, 1);
            vault.setRedeemOrderFee(originalFee);

            deal(address(asset), helperFiller, expected + 1_000e6);
            vm.prank(helperFiller);
            asset.approve(address(helper), type(uint256).max);
            vm.prank(helperFiller);
            helper.fillAndFinalizeRedeemOrder(orderId, expected + 1_000e6, block.timestamp + 1 days);

            assertEq(vault.getRedeemOrder(orderId).assets, expected, "row3: fee lower altered live settlement");
        }

        // Row 4: maxAssets under the true settled amount -- reverts cleanly, no state change.
        {
            vault.setRedeemOrderFee(50_000);
            address u = makeAddr("forkUser3row4");
            uint256 shares = _fundAndDeposit(u, 5_000e6);
            vm.prank(u);
            shareToken.approve(address(helper), type(uint256).max);
            uint256 expected = vault.previewRedeemOrder(shares);

            vm.prank(u);
            uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, u, 1_000_000, 100, 1);

            deal(address(asset), helperFiller, expected + 1_000e6);
            vm.prank(helperFiller);
            asset.approve(address(helper), type(uint256).max);
            uint256 fillerBalBefore = asset.balanceOf(helperFiller);

            vm.prank(helperFiller);
            vm.expectRevert();
            helper.fillAndFinalizeRedeemOrder(orderId, expected - 1, block.timestamp + 1 days);

            assertEq(uint256(vault.getRedeemOrder(orderId).status), uint256(OrderStatus.Pending), "row4: state changed");
            assertEq(asset.balanceOf(helperFiller), fillerBalBefore, "row4: filler balance changed");
            vault.setRedeemOrderFee(originalFee);
        }
    }

    // --- 4. The 11 pre-existing open orders are provably untouched -------------------------------

    function test_ForkScenario4_PreExistingOrdersUntouched() public {
        if (!_setUpFork()) return;

        uint256 orderCountBefore = vault.orderCount();
        assertGe(
            orderCountBefore, 11, "fewer pre-existing orders than the plan's snapshot -- re-verify the target vault"
        );

        Order[] memory snapshot = new Order[](orderCountBefore);
        for (uint256 i = 0; i < orderCountBefore; i++) {
            snapshot[i] = vault.getRedeemOrder(i);
        }
        uint256 pendingBefore = vault.totalPendingOrderSize();
        uint256 unfinalizedBefore = vault.totalUnfinalizedOrderValue();

        address forkUser = makeAddr("forkUser4");
        uint256 shares = _fundAndDeposit(forkUser, 5_000e6);
        vm.prank(forkUser);
        shareToken.approve(address(helper), type(uint256).max);
        uint256 expected = vault.previewRedeemOrder(shares);

        vm.prank(forkUser);
        uint256 orderId = helper.createRedeemOrderWithMaxFee(shares, forkUser, 1_000_000, 100, 1);
        deal(address(asset), helperFiller, expected + 1_000e6);
        vm.prank(helperFiller);
        asset.approve(address(helper), type(uint256).max);
        vm.prank(helperFiller);
        helper.fillAndFinalizeRedeemOrder(orderId, expected + 1_000e6, block.timestamp + 1 days);

        // A fully-settled create->fill->finalize cycle returns both aggregate counters to their
        // pre-existing baseline: `_totalPendingOrderSize` is added at creation and subtracted at
        // fill (`YuzuV3FacetBase.sol:79`, `YuzuILPV3Facet.sol:154`); `_totalUnfinalizedOrderValue`
        // is added at fill and subtracted at finalize (`YuzuILPV3Facet.sol:155`,
        // `YuzuV3FacetBase.sol:130`). Only `orderCount` should have moved.
        assertEq(vault.orderCount(), orderCountBefore + 1, "order count did not grow by exactly the new order");
        assertEq(vault.totalPendingOrderSize(), pendingBefore, "totalPendingOrderSize drifted after a settled cycle");
        assertEq(
            vault.totalUnfinalizedOrderValue(),
            unfinalizedBefore,
            "totalUnfinalizedOrderValue drifted after a settled cycle"
        );

        for (uint256 i = 0; i < orderCountBefore; i++) {
            Order memory current = vault.getRedeemOrder(i);
            assertEq(uint256(current.status), uint256(snapshot[i].status), "pre-existing order status changed");
            assertEq(current.assets, snapshot[i].assets, "pre-existing order assets changed");
            assertEq(current.tokens, snapshot[i].tokens, "pre-existing order tokens changed");
            assertEq(current.owner, snapshot[i].owner, "pre-existing order owner changed");
            assertEq(current.receiver, snapshot[i].receiver, "pre-existing order receiver changed");
            assertEq(current.controller, snapshot[i].controller, "pre-existing order controller changed");
            assertEq(current.dueTime, snapshot[i].dueTime, "pre-existing order dueTime changed");
            assertEq(current.feePpm, snapshot[i].feePpm, "pre-existing order feePpm changed");
        }
    }

    // --- 5. Helper coexists with the existing ORDER_FILLER_ROLE holder ---------------------------

    function test_ForkScenario5_CoexistsWithExistingOrderFillerRole() public {
        if (!_setUpFork()) return;

        // Our helper fills its own order.
        address forkUserA = makeAddr("forkUser5a");
        uint256 sharesA = _fundAndDeposit(forkUserA, 5_000e6);
        vm.prank(forkUserA);
        shareToken.approve(address(helper), type(uint256).max);
        uint256 expectedA = vault.previewRedeemOrder(sharesA);
        vm.prank(forkUserA);
        uint256 orderIdA = helper.createRedeemOrderWithMaxFee(sharesA, forkUserA, 1_000_000, 100, 1);
        deal(address(asset), helperFiller, expectedA + 1_000e6);
        vm.prank(helperFiller);
        asset.approve(address(helper), type(uint256).max);
        vm.prank(helperFiller);
        helper.fillAndFinalizeRedeemOrder(orderIdA, expectedA + 1_000e6, block.timestamp + 1 days);
        assertEq(uint256(vault.getRedeemOrder(orderIdA).status), uint256(OrderStatus.Finalized), "helper fill failed");

        // The pre-existing legacy filler independently fills a DIFFERENT order created directly on
        // the vault, proving the helper's role grant did not displace it.
        address forkUserB = makeAddr("forkUser5b");
        uint256 sharesB = _fundAndDeposit(forkUserB, 5_000e6);
        uint256 expectedB = vault.previewRedeemOrder(sharesB);
        vm.prank(forkUserB);
        uint256 orderIdB = vault.createRedeemOrder(sharesB, forkUserB, forkUserB);

        deal(address(asset), EXISTING_ORDER_FILLER, expectedB + 1_000e6);
        vm.prank(EXISTING_ORDER_FILLER);
        asset.approve(YZCASH, type(uint256).max);
        vm.prank(EXISTING_ORDER_FILLER);
        vault.fillRedeemOrder(orderIdB);
        vm.prank(forkUserB);
        vault.finalizeRedeemOrder(orderIdB);

        assertEq(
            uint256(vault.getRedeemOrder(orderIdB).status), uint256(OrderStatus.Finalized), "legacy filler fill failed"
        );
    }

    // --- 6. cancelOwnRedeemOrder refuses a pre-existing order (F3) --------------------------------

    function test_ForkScenario6_CancelOwnRedeemOrder_RefusesPreExistingOrder() public {
        if (!_setUpFork()) return;

        uint256 orderCountBefore = vault.orderCount();
        assertGt(orderCountBefore, 0, "no pre-existing orders to test against");

        address foreignController = vault.getRedeemOrder(0).controller;

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                YuzuRedeemOrderHelper.OrderNotControlledByHelper.selector, uint256(0), foreignController
            )
        );
        helper.cancelOwnRedeemOrder(0);
    }

    // --- 9. the restatement gate, against a live vault that is genuinely mid-update -------------

    /// @dev yzUSDe is a second live ILP V3 vault, and at the pinned block its pool update is
    /// actually staged on-chain (`isUpdatingPool() == true`). Every other restatement test sets
    /// that flag itself; this one does not touch it, so it proves the gate fires on real state
    /// rather than on a fixture.
    function test_ForkScenario9_RestatementGate_LiveVaultMidPoolUpdate() public {
        if (!_setUpFork()) return;

        YuzuRedeemOrderHelper midUpdateHelper = new YuzuRedeemOrderHelper(YZUSDE, USDC, admin, admin);

        assertTrue(IYuzuILPV2(YZUSDE).isUpdatingPool(), "pinned block no longer has a staged pool update");

        address someUser = makeAddr("forkMidUpdateUser");
        vm.prank(someUser);
        vm.expectRevert(abi.encodeWithSelector(YuzuRedeemOrderHelper.VaultSettlementClosed.selector, someUser));
        midUpdateHelper.createRedeemOrderWithMaxFee(1e18, someUser, 1_000_000, 100, 1);
    }
}
