// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IYuzuRedeemOrderHelper} from "../interfaces/IYuzuRedeemOrderHelper.sol";
import {IYuzuILPV2} from "../interfaces/IYuzuILP.sol";
import {IYuzuProto, IYuzuProtoV2} from "../interfaces/proto/IYuzuProto.sol";
import {Order, OrderStatus} from "../interfaces/proto/IYuzuOrderBookDefinitions.sol";

/**
 * @title YuzuRedeemOrderHelper
 * @notice Sits beside a single, immutable Yuzu V3 vault. A user creates a redeem order through
 * this helper (one `approve` + one call), which records the helper as the order `controller`. A
 * permissioned filler can then fill and finalize the order in one transaction — the user never
 * returns. No vault code is modified; the helper only holds `ORDER_FILLER_ROLE` on the vault and
 * calls its existing, unmodified order-book surface.
 *
 * @dev Custody and settlement invariants, all load-bearing:
 *
 * - Settlement never calls `previewRedeemOrder`, which prices at the vault's *current* fee, while
 *   `fillRedeemOrder` settles at the fee *stamped at order creation*. The two diverge whenever
 *   `setRedeemOrderFee` moves between creation and fill. Settlement instead pulls up to
 *   `maxAssets` from the filler, lets the vault discover the true settled amount, and refunds the
 *   difference — correct for any fee path, with no vault math reimplemented here.
 * - Every external call asserts a *balance delta*, never an absolute-zero balance. A third party
 *   can donate dust to this contract at any time; an absolute-zero assertion would let that dust
 *   permanently brick every future fill.
 * - `receiver` may never be this contract. The vault's `finalizeRedeemOrder` pays `order.receiver`
 *   from the vault's own balance, so a self-referential receiver credits this contract mid-call
 *   and makes the closing residual-balance equality unsatisfiable for every possible `maxAssets` —
 *   bricking the order's only fill path — while a vault-level force-fill would strand the payout
 *   here as un-owned balance. Rejected at both creation sites instead.
 * - `ORDER_FILLER_ROLE` on the vault also confers unconditional force-cancel of any pending order,
 *   bypassing the vault's pause check, its owner/controller check, and `dueTime` together. The
 *   only cancel path this contract exposes is `cancelOwnRedeemOrder`, which refuses every order
 *   whose `controller` is not this contract — the force-cancel power never becomes a primitive
 *   over the wider order book.
 * - A pause landing between fill and finalize makes the whole `fillAndFinalizeRedeemOrder` call
 *   revert; this is intentional. A partially-applied state where the filler paid and the user did
 *   not receive would be strictly worse. `finalizeRedeemOrder` (permissionless) and
 *   `cancelOwnRedeemOrder` (`ADMIN_ROLE`) are the recovery paths once the pause clears or the order
 *   is abandoned.
 *
 * @dev Two guards close gaps that only exist because this helper composes the vault's
 * deliberately *asynchronous* order path into a synchronous one:
 *
 * - **Restatement gate.** Both V3 vault families freeze their instant redeem path while a price
 *   restatement is staged — yzUSD through `canRedeem`, which folds in the NAV-update flag, and
 *   yzILP through `isUpdatingPool`. Neither freeze reaches `canCreateRedeemOrder`,
 *   `fillRedeemOrder` or `finalizeRedeemOrder`, because the order path was assumed slow enough
 *   that no holder could exit at the pre-restatement price. This helper deletes that assumption,
 *   so it re-imposes the freeze itself, in {_requireVaultSettlementOpen}. The two families expose
 *   the flag differently and `YuzuILPV2.canRedeem` is hardcoded `false` (ILP has no instant redeem
 *   path at all), so the predicate is selected once, at construction, by probing for
 *   `isUpdatingPool()`.
 * - **Owner price floor.** `fillRedeemOrder` prices at the fill block, and the filler picks that
 *   block; the owner cannot cancel before `dueTime`. `createRedeemOrderWithMaxFee` therefore
 *   requires a non-zero `minAssetsOut`, recorded per order and checked against the vault's own
 *   settled `order.assets` — never a pre-fill preview — on both helper payout paths: the fill
 *   (before finalize) and the finalize passthrough. Another vault `ORDER_FILLER_ROLE` holder can
 *   still fill a helper order at the vault below the floor; only helper fills honour it, so that
 *   role should be held by this helper alone.
 *
 * @dev Access and fee:
 *
 * - **Two admin tiers.** `DEFAULT_ADMIN_ROLE` (two-step transferable; the governance timelock)
 *   appoints and removes `ADMIN_ROLE` holders and transfers itself; it has no operational function
 *   of its own, though it can appoint itself. `ADMIN_ROLE` (the operator, set at construction)
 *   runs operations and appoints the operational roles. The deployer never holds `ADMIN_ROLE`.
 * - **Who may redeem.** The vault enforces its own `REDEEMER_ROLE` allowlist on the order owner at
 *   creation and at fill; this helper adds no second list.
 * - **Helper fee.** Charged in vault shares, and only for a redemption that happens. The fee is
 *   pulled from the owner at creation and held by this contract
 *   (`orderFeeTokens`, `totalEscrowedFeeShares`); the order is created for the remainder, so the
 *   owner needs no allowance or balance afterwards. {settleFee} resolves it from the vault's own
 *   order status: Finalized pays the current `feeRecipient` (refunds the owner if there is none),
 *   Cancelled refunds the owner, Pending or Filled waits. {fillAndFinalizeRedeemOrder},
 *   {finalizeRedeemOrder} and {cancelOwnRedeemOrder} settle it inline; an owner finalize or cancel
 *   at the vault is settled by anyone calling {settleFee}. Escrowed fees are excluded from
 *   {rescueTokens}. The owner caps the rate with `maxHelperFeeBps`. The fee never touches the
 *   asset, so `receiver` stays the user, finalize
 *   stays permissionless, and {_settle}'s asset residual check is unchanged. Rounded down, so it
 *   never exceeds `feeBps` of `tokens`; `MAX_FEE_BPS` bounds the rate.
 * - **Pause.** `PAUSE_MANAGER_ROLE` can stop creation; only `ADMIN_ROLE` can restart it.
 */
contract YuzuRedeemOrderHelper is IYuzuRedeemOrderHelper, AccessControlDefaultAdminRules, ReentrancyGuard, Pausable {
    bytes32 public constant FILLER_ROLE = keccak256("FILLER_ROLE");
    bytes32 public constant PAUSE_MANAGER_ROLE = keccak256("PAUSE_MANAGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Hard ceiling on `feeBps` (1%).
    uint16 public constant MAX_FEE_BPS = 100;

    IYuzuProto internal immutable _vault;
    IERC20 internal immutable _asset;

    /// @dev True when the bound vault answers `isUpdatingPool()` — the yzILP family. False for the
    /// yzUSD family, whose restatement freeze is reachable only through `canRedeem`. Probed once,
    /// at construction, because the two families expose no common predicate: `canRedeem` is
    /// hardcoded `false` on every yzILP vault, and `isUpdatingPool()` does not exist on yzUSD.
    bool internal immutable _vaultExposesPoolUpdateFlag;

    /// @inheritdoc IYuzuRedeemOrderHelper
    mapping(uint256 orderId => uint256 minAssetsOut) public orderMinAssetsOut;

    /// @inheritdoc IYuzuRedeemOrderHelper
    mapping(uint256 orderId => uint256 feeTokens) public orderFeeTokens;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint256 public totalEscrowedFeeShares;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint16 public feeBps;

    /// @inheritdoc IYuzuRedeemOrderHelper
    address public feeRecipient;

    error InvalidZeroAddress();
    error InvalidReceiver();
    error InvalidMinAssetsOut();
    error AssetMismatch(address expected, address actual);
    error ExecDeadlineExpired(uint256 execDeadline, uint256 blockTimestamp);
    error OrderNotPending(uint256 orderId);
    error OrderNotControlledByHelper(uint256 orderId, address controller);
    error MinAssetsOutNotMet(uint256 settled, uint256 minAssetsOut);
    error VaultSettlementClosed(address orderOwner);
    error ResidualBalanceMismatch(uint256 expected, uint256 actual);
    error FeeTooHigh(uint256 feeBps, uint256 maxFeeBps);
    error HelperFeeAboveMax(uint256 feeBps, uint256 maxHelperFeeBps);
    error FeeNotSettleable(uint256 orderId);
    error RescueExceedsFreeBalance(uint256 amount, uint256 free);

    /// @param vault_ The Yuzu V3 vault this helper is permanently bound to.
    /// @param asset_ The vault's underlying asset, checked against `vault_.asset()` below.
    /// @param admin_ Holds the two-step-transferable `DEFAULT_ADMIN_ROLE`, which only appoints
    /// `ADMIN_ROLE` holders.
    /// @param operator_ Initial `ADMIN_ROLE` holder: fee, pause recovery, cancels, role grants.
    // The only external call is the read-only `isUpdatingPool()` probe of the bound vault.
    // slither-disable-next-line pess-call-forward-to-protected
    constructor(address vault_, address asset_, address admin_, address operator_)
        AccessControlDefaultAdminRules(0, admin_)
    {
        if (vault_ == address(0) || asset_ == address(0) || admin_ == address(0) || operator_ == address(0)) {
            revert InvalidZeroAddress();
        }
        address vaultAsset = IYuzuProto(vault_).asset();
        if (vaultAsset != asset_) {
            revert AssetMismatch(asset_, vaultAsset);
        }
        _vault = IYuzuProto(vault_);
        _asset = IERC20(asset_);

        // Neither V3 router installs a catch-all fallback, so an absent `isUpdatingPool()` reverts
        // rather than returning empty success — the probe cannot mis-classify a yzUSD vault.
        // slither-disable-next-line low-level-calls,pess-arbitrary-call-destination-tainted
        (bool ok, bytes memory ret) = vault_.staticcall(abi.encodeCall(IYuzuILPV2.isUpdatingPool, ()));
        _vaultExposesPoolUpdateFlag = ok && ret.length == 32;

        _grantRole(ADMIN_ROLE, operator_);
        _setRoleAdmin(FILLER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PAUSE_MANAGER_ROLE, ADMIN_ROLE);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    // Trusted vault; the order id is only known after the vault call.
    // slither-disable-next-line reentrancy-benign
    function createRedeemOrderWithMaxFee(
        uint256 tokens,
        address receiver,
        uint256 maxFeePpm,
        uint256 maxHelperFeeBps,
        uint256 minAssetsOut
    ) external whenNotPaused returns (uint256 orderId) {
        _checkOrderTerms(receiver, minAssetsOut);
        address orderOwner = _msgSender();
        _requireVaultSettlementOpen(orderOwner);
        _checkHelperFee(maxHelperFeeBps);
        uint256 feeTokens = _feeFor(tokens);
        if (feeTokens != 0) {
            SafeERC20.safeTransferFrom(IERC20(address(_vault)), orderOwner, address(this), feeTokens);
        }
        // The vault's own createRedeemOrderWithMaxFee reverts FeeOverMaxFee; not reimplemented here.
        orderId = _vault.createRedeemOrderWithMaxFee(tokens - feeTokens, receiver, orderOwner, maxFeePpm);
        orderMinAssetsOut[orderId] = minAssetsOut;
        if (feeTokens != 0) {
            orderFeeTokens[orderId] = feeTokens;
            totalEscrowedFeeShares += feeTokens;
        }
        // slither-disable-next-line reentrancy-events
        emit CreatedRedeemOrder(orderId, orderOwner, receiver, tokens - feeTokens, maxFeePpm, minAssetsOut);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    // Trusted vault, and nonReentrant.
    // slither-disable-next-line reentrancy-benign
    function fillAndFinalizeRedeemOrder(uint256 orderId, uint256 maxAssets, uint256 execDeadline)
        external
        nonReentrant
    {
        _checkRole(FILLER_ROLE);
        _checkExecDeadline(execDeadline);

        Order memory order = _vault.getRedeemOrder(orderId);
        if (order.status != OrderStatus.Pending) {
            revert OrderNotPending(orderId);
        }
        if (order.controller != address(this)) {
            revert OrderNotControlledByHelper(orderId, order.controller);
        }
        _requireVaultSettlementOpen(order.owner);

        uint256 entryBalance = _asset.balanceOf(address(this));
        uint256 settled = _settle(orderId, maxAssets, orderMinAssetsOut[orderId], entryBalance);
        _settleFee(orderId);

        emit FilledAndFinalizedRedeemOrder(orderId, order.owner, order.receiver, maxAssets, settled);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    // slither-disable-next-line reentrancy-benign
    function finalizeRedeemOrder(uint256 orderId) external nonReentrant {
        // An order another vault filler filled below the owner's floor is not paid out through this
        // helper; its owner can still finalize it directly at the vault. Other states fall through
        // to the vault's own checks.
        Order memory order = _vault.getRedeemOrder(orderId);
        if (order.status == OrderStatus.Filled && order.assets < orderMinAssetsOut[orderId]) {
            revert MinAssetsOutNotMet(order.assets, orderMinAssetsOut[orderId]);
        }
        _vault.finalizeRedeemOrder(orderId);
        _settleFee(orderId);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    // slither-disable-next-line reentrancy-benign
    function cancelOwnRedeemOrder(uint256 orderId) external nonReentrant {
        _checkRole(ADMIN_ROLE);
        Order memory order = _vault.getRedeemOrder(orderId);
        if (order.controller != address(this)) {
            revert OrderNotControlledByHelper(orderId, order.controller);
        }
        _vault.cancelRedeemOrder(orderId);
        _settleFee(orderId);
        emit CancelledRedeemOrder(orderId, order.owner);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    function settleFee(uint256 orderId) external nonReentrant {
        _settleFee(orderId);
    }

    /// @notice Pauses order creation. An order already open stays fillable and finalizable.
    function pause() external {
        _checkRole(PAUSE_MANAGER_ROLE);
        _pause();
    }

    /// @notice Restarting is reserved to `ADMIN_ROLE`, so a pauser (ops signer, monitoring bot)
    /// can stop the helper but never re-open it.
    function unpause() external {
        _checkRole(ADMIN_ROLE);
        _unpause();
    }

    /// @notice Sets the helper fee. A non-zero rate needs a non-zero recipient.
    // Guarded by `_checkRole(ADMIN_ROLE)` in the body.
    // slither-disable-next-line pess-unprotected-setter
    function setFee(uint16 newFeeBps, address newFeeRecipient) external {
        _checkRole(ADMIN_ROLE);
        if (newFeeBps > MAX_FEE_BPS) {
            revert FeeTooHigh(newFeeBps, MAX_FEE_BPS);
        }
        if (newFeeBps != 0 && newFeeRecipient == address(0)) {
            revert InvalidZeroAddress();
        }
        // Shares sent to the vault proxy are unrecoverable; to this helper, admin-rescuable.
        if (newFeeRecipient == address(_vault) || newFeeRecipient == address(this)) {
            revert InvalidReceiver();
        }
        feeBps = newFeeBps;
        feeRecipient = newFeeRecipient;
        emit UpdatedFee(newFeeBps, newFeeRecipient);
    }

    /// @notice Recovers tokens sent to this contract by mistake or as a donation. Never required
    /// for correct operation: settlement's delta accounting already tolerates stray balances.
    /// Escrowed helper fees (vault shares) are owed to owners or `feeRecipient` and cannot be taken.
    function rescueTokens(address token, address to, uint256 amount) external {
        _checkRole(ADMIN_ROLE);
        if (token == address(_vault)) {
            uint256 free = IERC20(token).balanceOf(address(this)) - totalEscrowedFeeShares;
            if (amount > free) {
                revert RescueExceedsFreeBalance(amount, free);
            }
        }
        SafeERC20.safeTransfer(IERC20(token), to, amount);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    function vault() external view returns (address) {
        return address(_vault);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    function asset() external view returns (address) {
        return address(_asset);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    function vaultExposesPoolUpdateFlag() external view returns (bool) {
        return _vaultExposesPoolUpdateFlag;
    }

    /// @dev Reverts while the bound vault has a price restatement staged, so no order can be
    /// created or filled through this helper at the pre-restatement price. Finalize is not gated:
    /// it only pays the amount fixed at fill. yzILP is
    /// asked directly for `isUpdatingPool()`; yzUSD is asked for `canRedeem(owner)`, the only
    /// surface through which its private `_isUpdatingNav` flag is observable. `canRedeem` also
    /// folds in `paused()` and the redeemer allowlist, both of which already block this helper's
    /// paths inside the vault, so the extra terms narrow nothing that was previously reachable.
    function _requireVaultSettlementOpen(address orderOwner) internal view {
        if (_vaultExposesPoolUpdateFlag) {
            if (IYuzuILPV2(address(_vault)).isUpdatingPool()) {
                revert VaultSettlementClosed(orderOwner);
            }
        } else if (!IYuzuProtoV2(address(_vault)).canRedeem(orderOwner)) {
            revert VaultSettlementClosed(orderOwner);
        }
    }

    /// @dev The filler's own staleness guard, shared by every settlement entry point.
    function _checkExecDeadline(uint256 execDeadline) internal view {
        if (block.timestamp > execDeadline) {
            revert ExecDeadlineExpired(execDeadline, block.timestamp);
        }
    }

    /// @dev The caller's (or signer's) cap on the helper fee rate, so an admin `setFee` landing
    /// just before the order cannot raise the fee above what the owner agreed to.
    function _checkHelperFee(uint256 maxHelperFeeBps) internal view {
        uint256 rate = feeBps;
        if (rate > maxHelperFeeBps) {
            revert HelperFeeAboveMax(rate, maxHelperFeeBps);
        }
    }

    /// @dev The helper fee on `tokens` at the current rate, rounded down so it never exceeds
    /// `feeBps` of `tokens`.
    function _feeFor(uint256 tokens) internal view returns (uint256) {
        return Math.mulDiv(tokens, feeBps, 10_000);
    }

    /// @dev Resolves an escrowed fee from the vault's order status. No-op when nothing is escrowed
    /// (already settled, or the fee was zero). Pending or Filled reverts:
    /// the outcome is not known yet. Effects precede the transfer.
    function _settleFee(uint256 orderId) internal {
        uint256 feeTokens = orderFeeTokens[orderId];
        if (feeTokens == 0) {
            return;
        }
        Order memory order = _vault.getRedeemOrder(orderId);
        // A Filled order may still fail to finalize (vault paused, receiver blocked): the fee waits
        // until the payout has happened.
        if (order.status == OrderStatus.Pending || order.status == OrderStatus.Filled) {
            revert FeeNotSettleable(orderId);
        }
        delete orderFeeTokens[orderId];
        totalEscrowedFeeShares -= feeTokens;

        // The amount was fixed at creation; a later rate change applies to new orders only. With no
        // recipient there is nowhere to pay, so the owner gets it back.
        address recipient = feeRecipient;
        IERC20 shares = IERC20(address(_vault));
        if (order.status == OrderStatus.Cancelled || recipient == address(0)) {
            SafeERC20.safeTransfer(shares, order.owner, feeTokens);
            emit RefundedFee(orderId, order.owner, feeTokens);
        } else {
            SafeERC20.safeTransfer(shares, recipient, feeTokens);
            emit ChargedFee(orderId, order.owner, recipient, feeTokens);
        }
    }

    /// @dev The two order terms this contract validates on the owner's behalf, wherever an order
    /// originates. Kept in one place so no entry point can be added that silently omits either.
    /// A self-referential receiver makes {_settle}'s residual equality unsatisfiable, and the vault
    /// as receiver pays the vault itself; a zero floor makes its `settled < minAssetsOut` check
    /// unsatisfiable, which is not a floor at all.
    function _checkOrderTerms(address receiver, uint256 minAssetsOut) internal view {
        if (receiver == address(this) || receiver == address(_vault)) {
            revert InvalidReceiver();
        }
        if (minAssetsOut == 0) {
            revert InvalidMinAssetsOut();
        }
    }

    /// @dev The one settlement mechanism: pulls up to `maxAssets` from the caller, lets the vault
    /// discover the true settled amount, refunds the difference, and asserts the helper's asset
    /// balance delta is exactly zero against `entryBalance`. `previewRedeemOrder` never appears: it
    /// prices at the vault's *current* fee while `fillRedeemOrder` settles at the fee stamped at
    /// order creation.
    ///
    /// @param entryBalance The helper's asset balance snapshotted by the caller before settlement.
    function _settle(uint256 orderId, uint256 maxAssets, uint256 minAssetsOut, uint256 entryBalance)
        internal
        returns (uint256 settled)
    {
        address filler = _msgSender();
        SafeERC20.safeTransferFrom(_asset, filler, address(this), maxAssets);
        SafeERC20.forceApprove(_asset, address(_vault), maxAssets);

        // The vault pulls the exact stamped-fee amount from this contract's balance via its own
        // allowance check; if `maxAssets` is under that amount, this call reverts on insufficient
        // allowance and the whole transaction rolls back with no state change.
        _vault.fillRedeemOrder(orderId);

        SafeERC20.forceApprove(_asset, address(_vault), 0);

        settled = _vault.getRedeemOrder(orderId).assets;
        if (settled < minAssetsOut) {
            revert MinAssetsOutNotMet(settled, minAssetsOut);
        }
        if (maxAssets > settled) {
            SafeERC20.safeTransfer(_asset, filler, maxAssets - settled);
        }

        _vault.finalizeRedeemOrder(orderId);

        uint256 exitBalance = _asset.balanceOf(address(this));
        if (exitBalance != entryBalance) {
            revert ResidualBalanceMismatch(entryBalance, exitBalance);
        }
    }
}
