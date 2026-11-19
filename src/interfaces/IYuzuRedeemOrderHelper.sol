// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title IYuzuRedeemOrderHelper
 * @notice Surface for a helper deployed beside a single Yuzu V3 vault. A user creates a redeem
 * order through the helper so the helper is recorded as the order's `controller`, which lets a
 * permissioned filler `fill` and `finalize` the order in one transaction. The helper never
 * custodies the underlying asset across calls; between creation and settlement it holds only the
 * escrowed helper fee in vault shares — see `YuzuRedeemOrderHelper` for the custody invariants.
 * @dev `cancelRedeemOrder` is deliberately absent from this surface: `ORDER_FILLER_ROLE` on the
 * vault also confers unconditional force-cancel of any pending order, so the only reachable cancel
 * path is the narrowed `cancelOwnRedeemOrder`, restricted to orders this helper created.
 */
interface IYuzuRedeemOrderHelper {
    /// @notice Emitted when a user creates a redeem order through the helper.
    event CreatedRedeemOrder(
        uint256 indexed orderId,
        address indexed owner,
        address indexed receiver,
        uint256 tokens,
        uint256 maxFeePpm,
        uint256 minAssetsOut
    );

    /// @notice Emitted when a filler fills and finalizes an order through the helper in one call.
    event FilledAndFinalizedRedeemOrder(
        uint256 indexed orderId, address indexed owner, address indexed receiver, uint256 maxAssets, uint256 settled
    );

    /// @notice Emitted when the helper cancels an order it created.
    event CancelledRedeemOrder(uint256 indexed orderId, address indexed owner);

    /// @notice Emitted when the helper fee rate or recipient changes.
    event UpdatedFee(uint256 feeBps, address feeRecipient);

    /// @notice Emitted when an escrowed helper fee is paid to `feeRecipient`, in vault shares, once
    /// its order is finalized.
    event ChargedFee(uint256 indexed orderId, address indexed owner, address indexed feeRecipient, uint256 feeTokens);

    /// @notice Emitted when an escrowed helper fee is returned to the owner: the order was
    /// cancelled, or no fee recipient is set when it settles.
    event RefundedFee(uint256 indexed orderId, address indexed owner, uint256 feeTokens);

    /// @notice Emitted when an account is added to or removed from the helper whitelist.
    event UpdatedWhitelisted(address indexed account, bool allowed);

    /// @notice Emitted when the helper whitelist is turned on or off.
    event UpdatedWhitelistEnabled(bool enabled);

    /// @notice Emitted when the per-fill cap or the rolling 24h limits change.
    event UpdatedLimits(uint256 txCap, uint256 accountLimit, uint256 totalLimit);

    /// @notice Emitted when the slippage guard changes.
    event UpdatedMaxSlippage(uint16 maxSlippageBps);

    /// @notice Creates a redeem order with `owner = msg.sender` and `controller = address(this)`,
    /// forwarding to the vault's own max-fee check (the vault also enforces its `REDEEMER_ROLE`
    /// allowlist on the owner). While `whitelistEnabled`, the caller must be `isWhitelisted`, else
    /// `NotWhitelisted`; the same check runs again at fill. The helper fee is pulled from the
    /// caller's shares now and held in escrow (the order is for `tokens` minus it); see {settleFee}.
    /// @param tokens Vault shares to redeem, gross of the helper fee.
    /// @param receiver Address to receive the settled assets on finalize. May not be the helper:
    /// a self-referential receiver makes the settlement path's residual-balance equality
    /// unsatisfiable and strands the payout in the helper.
    /// @param maxFeePpm Caller's fee ceiling; the vault reverts `FeeOverMaxFee` above it.
    /// @param maxHelperFeeBps Caller's cap on the helper fee rate; reverts `HelperFeeAboveMax` if
    /// `feeBps` is above it (e.g. an admin `setFee` landed first).
    /// @param minAssetsOut The owner's price floor on the order's net settled assets (after both the
    /// vault fee and the helper fee), enforced after fill and before finalize against the vault's
    /// own settled `order.assets`. Must be non-zero: the filler chooses the fill block and the owner
    /// cannot cancel before `dueTime`, so without a floor the fill carries no owner-side protection
    /// against a price restatement in between.
    /// @return orderId The vault's order id.
    function createRedeemOrderWithMaxFee(
        uint256 tokens,
        address receiver,
        uint256 maxFeePpm,
        uint256 maxHelperFeeBps,
        uint256 minAssetsOut
    ) external returns (uint256 orderId);

    /// @notice Fills and finalizes a pending order the helper controls in one transaction, pulling
    /// at most `maxAssets` from the caller and refunding any unused amount. Reverts, leaving the
    /// order Pending, with `ExecDeadlineExpired`, `OrderNotPending`, `OrderNotControlledByHelper`,
    /// `VaultSettlementClosed` (pool update staged), `NotWhitelisted` (owner delisted since
    /// creation, while `whitelistEnabled`), `MinAssetsOutNotMet` (below the owner floor),
    /// `SlippageExceeded` (outside the band around the creation quote), or `AboveTxCap`,
    /// `AccountLimitExceeded` or `TotalLimitExceeded`.
    /// @param orderId The vault's order id.
    /// @param maxAssets Upper bound on the assets the caller is willing to pay; the caller's own
    /// slippage guard against a fee change or price move since order creation.
    /// @param execDeadline Caller's own staleness guard; reverts if `block.timestamp` exceeds it.
    function fillAndFinalizeRedeemOrder(uint256 orderId, uint256 maxAssets, uint256 execDeadline) external;

    /// @notice Permissionless passthrough to the vault's `finalizeRedeemOrder` for any filled order
    /// this helper controls (e.g. after a pause cleared, or one filled by another vault filler),
    /// then {settleFee}. Reverts `MinAssetsOutNotMet` for an order filled below its
    /// `orderMinAssetsOut`; only its owner can then finalize it, directly at the vault. Not gated by
    /// a staged restatement: it pays only the amount fixed at fill.
    function finalizeRedeemOrder(uint256 orderId) external;

    /// @notice Cancels a pending order the helper created, refusing every other order; restricted to
    /// `CANCEL_MANAGER_ROLE`. The vault returns the order's shares to the owner and the escrowed
    /// helper fee is refunded inline. This is the only reachable cancel path — see the
    /// contract-level note on why an unrestricted passthrough is never exposed.
    function cancelOwnRedeemOrder(uint256 orderId) external;

    /// @notice Resolves the escrowed helper fee of an order from the vault's order
    /// status: Finalized pays the current `feeRecipient` (or refunds the owner if there is none),
    /// Cancelled refunds the owner. Callable by anyone; a no-op once settled. Reverts
    /// `FeeNotSettleable` while the order is Pending or Filled (the payout has not happened yet).
    function settleFee(uint256 orderId) external;

    /// @notice The vault this helper is bound to.
    function vault() external view returns (address);

    /// @notice The underlying asset of `vault`.
    function asset() external view returns (address);

    /// @notice The owner's price floor recorded for `orderId` at creation, enforced at fill.
    function orderMinAssetsOut(uint256 orderId) external view returns (uint256);

    /// @notice The vault's quote for `orderId`'s payout, recorded at creation; the slippage guard's
    /// reference.
    function orderExpectedAssets(uint256 orderId) external view returns (uint256);

    /// @notice The helper fee, in vault shares, escrowed for an order at creation;
    /// zero once settled (charged or refunded).
    function orderFeeTokens(uint256 orderId) external view returns (uint256);

    /// @notice Sum of all escrowed helper fees; the share balance {rescueTokens} cannot touch.
    function totalEscrowedFeeShares() external view returns (uint256);

    /// @notice Helper fee in basis points of the shares redeemed, capped by `MAX_FEE_BPS`.
    function feeBps() external view returns (uint16);

    /// @notice Receives the helper fee, in vault shares.
    function feeRecipient() external view returns (address);

    /// @notice True while only `isWhitelisted` owners may create or be filled through the helper.
    /// On from construction.
    function whitelistEnabled() external view returns (bool);

    /// @notice Whether `account` is on the helper's partner whitelist.
    function isWhitelisted(address account) external view returns (bool);

    /// @notice Largest single payout, in asset units, a helper fill may settle. 0 blocks every fill.
    function txCap() external view returns (uint256);

    /// @notice Assets one order owner may receive through helper fills per rolling 24 hours.
    /// `type(uint256).max` disables it; 0 blocks every fill.
    function accountLimit() external view returns (uint256);

    /// @notice Assets all owners together may receive through helper fills per rolling 24 hours.
    /// `type(uint256).max` disables it; 0 blocks every fill.
    function totalLimit() external view returns (uint256);

    /// @notice Capacity `owner` has left under `accountLimit` now; `type(uint256).max` if disabled.
    function remainingAccountLimit(address owner) external view returns (uint256);

    /// @notice Capacity left under `totalLimit` now; `type(uint256).max` if disabled.
    function remainingTotalLimit() external view returns (uint256);

    /// @notice Largest allowed move, in basis points, of a helper fill's payout from
    /// `orderExpectedAssets`, in either direction. 0 means the guard is off.
    function maxSlippageBps() external view returns (uint16);
}
