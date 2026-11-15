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

    /// @notice Emitted when an escrowed two-transaction fee is returned to the owner: the order was
    /// cancelled, or no fee recipient is set when it settles.
    event RefundedFee(uint256 indexed orderId, address indexed owner, uint256 feeTokens);

    /// @notice Creates a redeem order with `owner = msg.sender` and `controller = address(this)`,
    /// forwarding to the vault's own max-fee check (the vault also enforces its `REDEEMER_ROLE`
    /// allowlist on the owner). The helper fee is pulled from the caller's shares now and held in
    /// escrow (the order is for `tokens` minus it); see {settleFee}.
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
    /// at most `maxAssets` from the caller and refunding any unused amount.
    /// @param orderId The vault's order id.
    /// @param maxAssets Upper bound on the assets the caller is willing to pay; the caller's own
    /// slippage guard against a fee change or NAV move since order creation.
    /// @param execDeadline Caller's own staleness guard; reverts if `block.timestamp` exceeds it.
    function fillAndFinalizeRedeemOrder(uint256 orderId, uint256 maxAssets, uint256 execDeadline) external;

    /// @notice Permissionless passthrough to the vault's `finalizeRedeemOrder` for any filled order
    /// this helper controls (e.g. after a pause cleared, or one filled by another vault filler),
    /// then {settleFee}. Reverts `MinAssetsOutNotMet` for an order filled below its
    /// `orderMinAssetsOut`; only its owner can then finalize it, directly at the vault. Not gated by
    /// a staged restatement: it pays only the amount fixed at fill.
    function finalizeRedeemOrder(uint256 orderId) external;

    /// @notice Cancels a pending order the helper created, refusing every other order. This is the
    /// only reachable cancel path — see the contract-level note on why an unrestricted passthrough
    /// is never exposed.
    function cancelOwnRedeemOrder(uint256 orderId) external;

    /// @notice Resolves the escrowed helper fee of a two-transaction order from the vault's order
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

    /// @notice The helper fee, in vault shares, escrowed for a two-transaction order at creation;
    /// zero once settled (charged or refunded).
    function orderFeeTokens(uint256 orderId) external view returns (uint256);

    /// @notice Sum of all escrowed helper fees; the share balance {rescueTokens} cannot touch.
    function totalEscrowedFeeShares() external view returns (uint256);

    /// @notice Helper fee in basis points of the shares redeemed, capped by `MAX_FEE_BPS`.
    function feeBps() external view returns (uint16);

    /// @notice Receives the helper fee, in vault shares.
    function feeRecipient() external view returns (address);

    /// @notice True when the bound vault is a yzILP-family vault, whose price-restatement freeze
    /// is read from `isUpdatingPool()`. False for the yzUSD family, read from `canRedeem`.
    function vaultExposesPoolUpdateFlag() external view returns (bool);
}
