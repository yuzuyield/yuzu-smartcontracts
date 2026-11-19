// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControlDefaultAdminRules} from
    "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IYuzuRedeemOrderHelper} from "../interfaces/IYuzuRedeemOrderHelper.sol";
import {IYuzuILPV2} from "../interfaces/IYuzuILP.sol";
import {IYuzuILPV3Router} from "../interfaces/IYuzuV3FacetRouters.sol";
import {IYuzuProto} from "../interfaces/proto/IYuzuProto.sol";
import {Order, OrderStatus} from "../interfaces/proto/IYuzuOrderBookDefinitions.sol";

/**
 * @title YuzuRedeemOrderHelper
 * @notice Sits beside a single, immutable yzILP V3 vault. A user creates a redeem order through
 * this helper (one `approve` + one call), which records the helper as the order `controller`. A
 * permissioned filler can then fill and finalize the order in one transaction — the user never
 * returns. No vault code is modified; the helper only holds `ORDER_FILLER_ROLE` on the vault and
 * calls its existing, unmodified order-book surface. Only yzILP V3 is supported: the constructor
 * reverts on a vault without `isUpdatingPool()` and `highWaterMark()`.
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
 *   here as un-owned balance. Rejected at creation instead (see {_checkOrderTerms}).
 * - `ORDER_FILLER_ROLE` on the vault also confers unconditional force-cancel of any pending order,
 *   bypassing the vault's pause check, its owner/controller check, and `dueTime` together. The
 *   only cancel path this contract exposes is `cancelOwnRedeemOrder`, which refuses every order
 *   whose `controller` is not this contract — the force-cancel power never becomes a primitive
 *   over the wider order book.
 * - A pause landing between fill and finalize makes the whole `fillAndFinalizeRedeemOrder` call
 *   revert; this is intentional. A partially-applied state where the filler paid and the user did
 *   not receive would be strictly worse. `finalizeRedeemOrder` (permissionless) and
 *   `cancelOwnRedeemOrder` (`CANCEL_MANAGER_ROLE`) are the recovery paths once the pause clears or
 *   the order is abandoned.
 *
 * @dev Two guards close gaps that only exist because this helper composes the vault's
 * deliberately *asynchronous* order path into a synchronous one:
 *
 * - **Restatement gate.** yzILP freezes pricing while a pool restatement is staged
 *   (`isUpdatingPool`), but that freeze never reaches `canCreateRedeemOrder`, `fillRedeemOrder`
 *   or `finalizeRedeemOrder`, because the order path was assumed slow enough that no holder could
 *   exit at the pre-restatement price. This helper deletes that assumption, so it re-imposes the
 *   freeze itself, in {_requireVaultSettlementOpen}.
 * - **Owner price floor.** `fillRedeemOrder` prices at the fill block, and the filler picks that
 *   block; the owner cannot cancel before `dueTime`. `createRedeemOrderWithMaxFee` therefore
 *   requires a non-zero `minAssetsOut`, recorded per order and checked against the vault's own
 *   settled `order.assets` — never a pre-fill preview — on both helper payout paths: the fill
 *   (before finalize) and the finalize passthrough. A fill made directly at the vault by another
 *   `ORDER_FILLER_ROLE` holder skips the floor; see **Sole vault filler** below.
 * - **Sole vault filler (deployment requirement).** The owner floor, the whitelist and the outflow
 *   limits bind only fills made through this helper. Any other holder of the vault's
 *   `ORDER_FILLER_ROLE` can fill a helper order directly at the vault, bypassing all three, and can
 *   force-cancel it. Once this helper is live on a vault, it must be the only `ORDER_FILLER_ROLE`
 *   holder there. The code does not assume this, because existing fillers keep the role during
 *   rollout: as a fallback, {finalizeRedeemOrder} refuses to pay out an order another filler filled
 *   below its floor, and a force-cancelled order's fee is refunded through {settleFee}.
 *
 * @dev Access and fee:
 *
 * - **Two admin tiers.** `DEFAULT_ADMIN_ROLE` (two-step transferable; the governance timelock)
 *   appoints and removes `ADMIN_ROLE` holders and transfers itself; it has no operational function
 *   of its own, though it can appoint itself. `ADMIN_ROLE` (the operator, set at construction)
 *   runs operations and appoints the operational roles. The deployer never holds `ADMIN_ROLE`.
 * - **Who may redeem.** Two lists, both on the order owner, and the helper's never replaces the
 *   vault's. The vault enforces its own `REDEEMER_ROLE` allowlist (when `isRedeemRestricted`) at
 *   creation and at fill. While `whitelistEnabled`, this helper also requires its partner list
 *   (`isWhitelisted`, managed by `WHITELIST_MANAGER_ROLE`):
 *   - Checked at creation and again at the helper fill, so delisting a partner also stops the fill
 *     of their pending orders.
 *   - Never checked on a recovery path: {finalizeRedeemOrder}, {settleFee}, {cancelOwnRedeemOrder},
 *     and the owner's own vault cancel after `dueTime`. A delisted owner always gets either the
 *     payout of an order already filled or the shares of one not filled; delisting never traps funds.
 *   - On from construction (fail closed). Only `ADMIN_ROLE` can switch it, and switching keeps the
 *     list: off opens the helper to every holder the vault allows, on restores the same partners.
 *   - Gates who requests, not who receives: `receiver` is free, and shares are transferable, so a
 *     listed owner can redeem shares it was sent.
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
 * - **Pause.** `PAUSE_MANAGER_ROLE` can stop creation; only `UNPAUSE_MANAGER_ROLE` can restart it.
 *   The two are separate roles so a pauser (ops signer, monitoring bot) can stop the helper but
 *   never re-open it, and re-opening can sit with a slower signer.
 *
 * @dev Outflow limits, set by `LIMIT_MANAGER_ROLE` and checked on every helper fill, in asset units
 * against the vault's own settled `order.assets`. A fill that breaks one reverts whole; the order
 * stays Pending for a later fill or a cancel. Orders consume nothing at creation, so a user cannot
 * reserve or burn capacity without the filler paying.
 *
 * - **Per-fill cap** (`txCap`) on a single order's payout.
 * - **Per-owner limit** (`accountLimit`) and **total limit** (`totalLimit`) over a rolling 24 hours,
 *   modelled as linear refill: recorded usage decays by the current limit per `LIMIT_WINDOW` and
 *   clears fully once `LIMIT_WINDOW` passes without a fill. The account is the vault order `owner`,
 *   which only the owner can set (it is `msg.sender` at creation), so one user cannot spend
 *   another's limit. Bound: no burst above the limit, and at most twice the limit in any 24 hours
 *   (a full bucket at the start plus a full refill by the end), unlike a UTC-day reset, which
 *   allows twice the limit within seconds of midnight.
 * - All three default to 0 (fail closed: nothing fills until configured). `type(uint256).max`
 *   disables a limit and stops recording usage for it. Lowering a limit below current usage blocks
 *   fills until usage decays at the new rate; raising one takes effect at once.
 * - The limits bind only fills through this helper; see **Sole vault filler** above.
 *
 * @dev Slippage guard, set by `LIMIT_MANAGER_ROLE` via {setMaxSlippage} (`maxSlippageBps`,
 * 0 = off). At creation the helper records the vault's own quote for the order
 * (`orderExpectedAssets`), exact in that transaction because the order's fee is stamped in it; a
 * zero quote is rejected. A helper fill then reverts if the settled payout moves more than
 * `maxSlippageBps` from the quote in either direction (bands round up). The band is flat: it does
 * not widen with order age. Size it above the largest legitimate price move within the vault's
 * `fillWindow` (linear yield, a distribution, a restatement); a larger move blocks helper fills of
 * older orders until `LIMIT_MANAGER_ROLE` widens the band, `CANCEL_MANAGER_ROLE` cancels, or the
 * owner cancels at the vault after `dueTime`. The guard bounds price movement between creation
 * and fill only; it does not judge whether the vault price is right. Like the limits, it binds
 * only fills through this helper.
 */
contract YuzuRedeemOrderHelper is IYuzuRedeemOrderHelper, AccessControlDefaultAdminRules, ReentrancyGuard, Pausable {
    bytes32 public constant FILLER_ROLE = keccak256("FILLER_ROLE");
    bytes32 public constant PAUSE_MANAGER_ROLE = keccak256("PAUSE_MANAGER_ROLE");
    bytes32 public constant UNPAUSE_MANAGER_ROLE = keccak256("UNPAUSE_MANAGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant WHITELIST_MANAGER_ROLE = keccak256("WHITELIST_MANAGER_ROLE");
    bytes32 public constant LIMIT_MANAGER_ROLE = keccak256("LIMIT_MANAGER_ROLE");

    /// @notice Cancels pending helper orders ({cancelOwnRedeemOrder}). Kept apart from
    /// `ADMIN_ROLE` so the emergency cancel can sit with a fast signer while `ADMIN_ROLE` sits
    /// behind a timelock.
    bytes32 public constant CANCEL_MANAGER_ROLE = keccak256("CANCEL_MANAGER_ROLE");

    /// @notice Hard ceiling on `feeBps` (1%).
    uint16 public constant MAX_FEE_BPS = 100;

    /// @notice Refill period of `accountLimit` and `totalLimit`.
    uint256 public constant LIMIT_WINDOW = 1 days;

    /// @notice Hard ceiling on `maxSlippageBps` (20%).
    uint16 public constant MAX_SLIPPAGE_BPS = 2_000;

    /// @dev The vault's order-filler role, which the helper must hold to fill and force-cancel.
    bytes32 internal constant VAULT_ORDER_FILLER_ROLE = keccak256("ORDER_FILLER_ROLE");

    /// @dev Outflow recorded against a rolling limit, as of `updatedAt`.
    struct LimitUsage {
        uint192 used;
        uint64 updatedAt;
    }

    IYuzuProto internal immutable _vault;
    IERC20 internal immutable _asset;

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

    /// @inheritdoc IYuzuRedeemOrderHelper
    bool public whitelistEnabled;

    /// @inheritdoc IYuzuRedeemOrderHelper
    mapping(address account => bool) public isWhitelisted;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint256 public txCap;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint256 public accountLimit;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint256 public totalLimit;

    /// @inheritdoc IYuzuRedeemOrderHelper
    uint16 public maxSlippageBps;

    /// @inheritdoc IYuzuRedeemOrderHelper
    mapping(uint256 orderId => uint256 assets) public orderExpectedAssets;

    mapping(address owner => LimitUsage) internal _accountUsage;
    LimitUsage internal _totalUsage;

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
    error NotWhitelisted(address orderOwner);
    error AboveTxCap(uint256 assets, uint256 txCap);
    error AccountLimitExceeded(address orderOwner, uint256 assets, uint256 remaining);
    error TotalLimitExceeded(uint256 assets, uint256 remaining);
    error InvalidLimit(uint256 limit);
    error SlippageTooHigh(uint256 maxSlippageBps, uint256 ceiling);
    error SlippageExceeded(uint256 settled, uint256 low, uint256 high);
    error ZeroQuote();
    error HelperNotVaultFiller();

    /// @param vault_ The yzILP V3 vault this helper is permanently bound to.
    /// @param asset_ The vault's underlying asset, checked against `vault_.asset()` below.
    /// @param admin_ Holds the two-step-transferable `DEFAULT_ADMIN_ROLE`, which only appoints
    /// `ADMIN_ROLE` holders.
    /// @param operator_ Initial `ADMIN_ROLE` holder: fee, whitelist switch, rescue, role grants.
    // The only external calls are read-only views of the bound vault.
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

        // yzILP V3 only: a vault without `isUpdatingPool()` (yzUSD) or the V3 fee views (yzILP V1
        // and V2) reverts here, at deployment, rather than running on unmodelled pricing.
        IYuzuILPV2(vault_).isUpdatingPool();
        IYuzuILPV3Router(vault_).highWaterMark();

        _grantRole(ADMIN_ROLE, operator_);
        _setRoleAdmin(FILLER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PAUSE_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(UNPAUSE_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(WHITELIST_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(LIMIT_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(CANCEL_MANAGER_ROLE, ADMIN_ROLE);

        whitelistEnabled = true;
        emit UpdatedWhitelistEnabled(true);
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
        _checkWhitelisted(orderOwner);
        // Without the vault's ORDER_FILLER_ROLE the helper can neither fill nor force-cancel, so an
        // order accepted now could only be recovered by the owner at the vault after `dueTime`.
        if (!IAccessControl(address(_vault)).hasRole(VAULT_ORDER_FILLER_ROLE, address(this))) {
            revert HelperNotVaultFiller();
        }
        _checkHelperFee(maxHelperFeeBps);
        uint256 feeTokens = _feeFor(tokens);
        if (feeTokens != 0) {
            SafeERC20.safeTransferFrom(IERC20(address(_vault)), orderOwner, address(this), feeTokens);
        }
        // The vault's own createRedeemOrderWithMaxFee reverts FeeOverMaxFee; not reimplemented here.
        orderId = _vault.createRedeemOrderWithMaxFee(tokens - feeTokens, receiver, orderOwner, maxFeePpm);
        orderMinAssetsOut[orderId] = minAssetsOut;
        // Exact in this transaction: the order's fee was stamped by the call above.
        uint256 quote = _vault.previewRedeemOrder(tokens - feeTokens);
        if (quote == 0) {
            revert ZeroQuote();
        }
        orderExpectedAssets[orderId] = quote;
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
        _checkWhitelisted(order.owner);

        uint256 entryBalance = _asset.balanceOf(address(this));
        uint256 settled = _settle(orderId, maxAssets, orderMinAssetsOut[orderId], entryBalance);
        _checkSlippage(orderId, settled);
        _consumeLimits(order.owner, settled);
        _settleFee(orderId);

        emit FilledAndFinalizedRedeemOrder(orderId, order.owner, order.receiver, maxAssets, settled);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    // slither-disable-next-line reentrancy-benign
    function finalizeRedeemOrder(uint256 orderId) external nonReentrant {
        // Fallback for the sole-filler requirement (see the contract note): an order another vault
        // filler filled below the owner's floor is not paid out through this helper. Its owner can
        // still accept it by finalizing directly at the vault. Other states fall through to the
        // vault's own checks.
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
        _checkRole(CANCEL_MANAGER_ROLE);
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

    /// @notice Restarting is reserved to `UNPAUSE_MANAGER_ROLE`, separate from
    /// `PAUSE_MANAGER_ROLE`, so a pauser can stop the helper but never re-open it.
    function unpause() external {
        _checkRole(UNPAUSE_MANAGER_ROLE);
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
        // The vault is not a fee recipient (its shares there are pending-order escrow, recoverable
        // only through a vault admin rescue); this helper would hold them as un-owned balance.
        if (newFeeRecipient == address(_vault) || newFeeRecipient == address(this)) {
            revert InvalidReceiver();
        }
        feeBps = newFeeBps;
        feeRecipient = newFeeRecipient;
        emit UpdatedFee(newFeeBps, newFeeRecipient);
    }

    /// @notice Adds or removes partners from the helper whitelist. Removal also blocks the fill of
    /// any of their orders still pending.
    // Guarded by `_checkRole(WHITELIST_MANAGER_ROLE)` in the body.
    // slither-disable-next-line pess-unprotected-setter
    function setWhitelisted(address[] calldata accounts, bool allowed) external {
        _checkRole(WHITELIST_MANAGER_ROLE);
        for (uint256 i = 0; i < accounts.length; ++i) {
            isWhitelisted[accounts[i]] = allowed;
            emit UpdatedWhitelisted(accounts[i], allowed);
        }
    }

    /// @notice Turns the helper whitelist on or off. Off opens the helper to every holder the vault
    /// itself allows to redeem, so it is reserved to `ADMIN_ROLE`.
    // Guarded by `_checkRole(ADMIN_ROLE)` in the body.
    // slither-disable-next-line pess-unprotected-setter
    function setWhitelistEnabled(bool enabled) external {
        _checkRole(ADMIN_ROLE);
        whitelistEnabled = enabled;
        emit UpdatedWhitelistEnabled(enabled);
    }

    /// @notice Sets the per-fill cap and the rolling 24h per-owner and total limits, in asset units.
    /// `type(uint256).max` disables a limit; a rolling limit is otherwise capped at
    /// `type(uint192).max` so its usage always fits the packed slot.
    // Guarded by `_checkRole(LIMIT_MANAGER_ROLE)` in the body.
    // slither-disable-next-line pess-unprotected-setter
    function setLimits(uint256 newTxCap, uint256 newAccountLimit, uint256 newTotalLimit) external {
        _checkRole(LIMIT_MANAGER_ROLE);
        _checkRollingLimit(newAccountLimit);
        _checkRollingLimit(newTotalLimit);
        txCap = newTxCap;
        accountLimit = newAccountLimit;
        totalLimit = newTotalLimit;
        emit UpdatedLimits(newTxCap, newAccountLimit, newTotalLimit);
    }

    /// @notice Sets the slippage guard: the largest allowed move, in basis points, of a helper
    /// fill's payout from the quote recorded at order creation. 0 turns the guard off. The band is
    /// read at fill, so a change applies at once to every pending order: widening it lets orders
    /// blocked by a legitimate price move fill, tightening it can block pending orders until they
    /// are cancelled or the band is widened again.
    // Guarded by `_checkRole(LIMIT_MANAGER_ROLE)` in the body.
    // slither-disable-next-line pess-unprotected-setter
    function setMaxSlippage(uint16 newMaxSlippageBps) external {
        _checkRole(LIMIT_MANAGER_ROLE);
        if (newMaxSlippageBps > MAX_SLIPPAGE_BPS) {
            revert SlippageTooHigh(newMaxSlippageBps, MAX_SLIPPAGE_BPS);
        }
        maxSlippageBps = newMaxSlippageBps;
        emit UpdatedMaxSlippage(newMaxSlippageBps);
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
    function remainingAccountLimit(address orderOwner) external view returns (uint256) {
        return _remaining(_accountUsage[orderOwner], accountLimit);
    }

    /// @inheritdoc IYuzuRedeemOrderHelper
    function remainingTotalLimit() external view returns (uint256) {
        return _remaining(_totalUsage, totalLimit);
    }

    /// @dev Reverts while the bound vault has a pool restatement staged, so no order can be
    /// created or filled through this helper at the pre-restatement price. Finalize is not gated:
    /// it only pays the amount fixed at fill.
    function _requireVaultSettlementOpen(address orderOwner) internal view {
        if (IYuzuILPV2(address(_vault)).isUpdatingPool()) {
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

    function _checkWhitelisted(address orderOwner) internal view {
        if (whitelistEnabled && !isWhitelisted[orderOwner]) {
            revert NotWhitelisted(orderOwner);
        }
    }

    function _checkRollingLimit(uint256 limit) internal pure {
        if (limit != type(uint256).max && limit > type(uint192).max) {
            revert InvalidLimit(limit);
        }
    }

    /// @dev Reverts when `settled` is more than `maxSlippageBps` away from the creation quote, in
    /// either direction. Bands round up. Skipped while the guard is off.
    function _checkSlippage(uint256 orderId, uint256 settled) internal view {
        uint256 bps = maxSlippageBps;
        if (bps == 0) {
            return;
        }
        uint256 expected = orderExpectedAssets[orderId];
        uint256 band = Math.mulDiv(expected, bps, 10_000, Math.Rounding.Ceil);
        uint256 low = expected - band;
        uint256 high = expected + band;
        if (settled < low || settled > high) {
            revert SlippageExceeded(settled, low, high);
        }
    }

    /// @dev Enforces all three outflow limits on a settled payout and records it against the two
    /// rolling ones. A disabled (`type(uint256).max`) rolling limit is skipped without a write.
    function _consumeLimits(address orderOwner, uint256 assets) internal {
        uint256 cap = txCap;
        if (assets > cap) {
            revert AboveTxCap(assets, cap);
        }
        uint256 limit = accountLimit;
        if (limit != type(uint256).max) {
            uint256 remaining = _consume(_accountUsage[orderOwner], limit, assets);
            if (assets > remaining) {
                revert AccountLimitExceeded(orderOwner, assets, remaining);
            }
        }
        limit = totalLimit;
        if (limit != type(uint256).max) {
            uint256 remaining = _consume(_totalUsage, limit, assets);
            if (assets > remaining) {
                revert TotalLimitExceeded(assets, remaining);
            }
        }
    }

    /// @dev Returns the capacity before this fill and records the fill only when it fits. The
    /// stored sum stays at or under `limit`, itself at most `type(uint192).max`, so the cast is exact.
    function _consume(LimitUsage storage usage, uint256 limit, uint256 assets) internal returns (uint256 remaining) {
        uint256 used = _usedNow(usage, limit);
        remaining = limit > used ? limit - used : 0;
        if (assets <= remaining) {
            // Exact: used + assets <= limit <= type(uint192).max; block.timestamp fits uint64.
            // slither-disable-next-line pess-dubious-typecast
            usage.used = uint192(used + assets);
            // slither-disable-next-line pess-dubious-typecast
            usage.updatedAt = uint64(block.timestamp);
        }
    }

    function _remaining(LimitUsage storage usage, uint256 limit) internal view returns (uint256) {
        if (limit == type(uint256).max) {
            return limit;
        }
        uint256 used = _usedNow(usage, limit);
        return limit > used ? limit - used : 0;
    }

    /// @dev Usage decays linearly by `limit` per `LIMIT_WINDOW` and clears once a full window
    /// passes with no fill, which also drops usage left above a since-lowered limit.
    function _usedNow(LimitUsage storage usage, uint256 limit) internal view returns (uint256) {
        LimitUsage memory snapshot = usage;
        uint256 elapsed = block.timestamp - snapshot.updatedAt;
        if (elapsed >= LIMIT_WINDOW) {
            return 0;
        }
        uint256 decay = Math.mulDiv(limit, elapsed, LIMIT_WINDOW);
        return snapshot.used > decay ? snapshot.used - decay : 0;
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

    /// @dev The two order terms this contract validates on the owner's behalf at creation. Kept in
    /// one place so a future entry point cannot silently omit either.
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
