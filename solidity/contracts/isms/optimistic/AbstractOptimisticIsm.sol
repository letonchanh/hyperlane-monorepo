// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {OptimisticIsmErrors} from "./OptimisticIsmErrors.sol";
import {Message} from "../../libs/Message.sol";

/**
 * @title OptimisticIsm - the optimistic verification security model.
 * @notice OptimisticIsm security model prioritizes safety over liveness;
 * the increased message latency allows for the addition of a second layer
 * of security, the watchers, without significant increases in gas costs.
 */
abstract contract AbstractOptimisticIsm is IOptimisticIsm, OptimisticIsmErrors {
    using Message for bytes;

    // ============ Constants ============

    // solhint-disable-next-line const-name-snakecase
    uint8 public constant moduleType =
        uint8(IInterchainSecurityModule.Types.OPTIMISTIC);

    // ============ Events ============
    /**
     * @notice Emitted when a message is pre-verified
     * @dev messageId is not indexed to save gas. Set it to indexed if there will be look ups by messageId.
     * @param messageId The unique identifier of the pre-verified message
     * @param submodule The address of the submodule that pre-verified the message
     * @param timestamp The block timestamp when the message was pre-verified
     */
    event PreVerified(bytes32 messageId, address submodule, uint256 timestamp);

    // ============ State Variables ============

    /// @notice Stores the pre-verification information of a message.
    /// @dev If a message is pre-verified successfully, the verification
    /// information, the ISM performing the pre-verifition and the timestamp,
    /// are stored into the two below mappings.
    mapping(bytes32 => address) internal preVerifiedByIsm;
    mapping(bytes32 => uint256) internal preVerifiedAtTimestamp;

    // ============ Virtual Functions ============
    // ======= OVERRIDE THESE TO IMPLEMENT =======

    /// @inheritdoc IOptimisticIsm
    function submodule(
        bytes calldata _message
    ) public view virtual returns (IInterchainSecurityModule);

    /**
     * @notice Returns the fraud window in seconds for a given message.
     * @param _message Hyperlane formatted interchain message.
     */
    function fraudWindow(
        bytes calldata _message
    ) public view virtual returns (uint256);

    /**
     * @notice Check if a submodule is fraudulent before or at a given timestamp.
     * @param _submodule The address of the submodule to check.
     * @param _timestamp The timestamp to check.
     * @return True if the submodule is fraudulent.
     */
    function isFraudulentAt(
        address _submodule,
        uint256 _timestamp
    ) public view virtual returns (bool);

    // ============ Public Functions ============

    /// @inheritdoc IOptimisticIsm
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) public override returns (bool verified) {
        bytes32 messageId = _message.id();

        /// @dev If the message has already been pre-verified, revert.
        /// Here, we only allow one pre-verification per message to ensure
        /// the liveness. If the message is pre-verified multiple times
        /// and the pre-verification timestamp is kept updating,
        /// the fraud window may never be elapsed and
        /// the message may never be delivered.
        /// Allowing multiple pre-verifications may also lead to
        /// the situation where the message is pre-verified by a fraudulent
        /// ISM, but then the recorded fraudulent ISM is overridden by a
        /// later pre-verification by a non-fraudulent ISM (which may be
        /// marked as fraudulent after the fraud window elapses).
        if (preVerifiedAtTimestamp[messageId] != 0) {
            revert AlreadyPreVerified();
        }

        IInterchainSecurityModule _submodule = submodule(_message);
        verified =
            !isFraudulentAt(address(_submodule), block.timestamp) &&
            _submodule.verify(_metadata, _message);

        preVerifiedAtTimestamp[messageId] = block.timestamp;
        if (verified) {
            preVerifiedByIsm[messageId] = address(_submodule);
            emit PreVerified(messageId, address(_submodule), block.timestamp);
        }
    }

    /// @inheritdoc IInterchainSecurityModule
    function verify(
        bytes calldata,
        bytes calldata _message
    ) public view override returns (bool) {
        bytes32 messageId = _message.id();
        address preVerifiedSubmodule = preVerifiedByIsm[messageId];

        /// @dev If the message has not been pre-verified successfully, return false.
        if (preVerifiedSubmodule == address(0)) {
            return false;
        }

        uint256 elapsedTime = preVerifiedAtTimestamp[messageId] +
            fraudWindow(_message);

        /// @dev If the ISM submodule has been flagged as fraudulent
        /// before the fraud window has elapsed, return false.
        if (isFraudulentAt(preVerifiedSubmodule, elapsedTime)) {
            return false;
        }

        /// @dev If the fraud window has not elapsed, return false.
        if (block.timestamp < elapsedTime) {
            return false;
        }

        return true;
    }
}
