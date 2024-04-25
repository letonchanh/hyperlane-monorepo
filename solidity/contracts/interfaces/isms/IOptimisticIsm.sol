// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

interface IOptimisticIsm is IInterchainSecurityModule {
    /**
     * @notice Pre-verifies _message by the submodule in OptimisticIsm.
     * @param _metadata Off-chain metadata provided by a relayer, specific to
     * the security model encoded by the submodule.
     * @param _message Hyperlane encoded interchain message (see Message.sol).
     * @return True if the message was verified.
     */
    function preVerify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external returns (bool);

    /**
     * @notice Marks a submodule as fraudulent.
     * @param _submodule The address of the submodule to mark as fraudulent.
     */
    function markFraudulent(address _submodule) external;

    /**
     * @notice Returns the submodule responsible for pre-verifying a given message.
     * @param _message Hyperlane formatted interchain message.
     * @return submodule The ISM used or to use to pre-verify the message.
     */
    function submodule(
        bytes calldata _message
    ) external view returns (IInterchainSecurityModule);

    /**
     * @notice Returns the set of watchers responsible for marking
     * ISMs as fraudulent.
     * @dev Can change based on the content of _message
     * @param _message Hyperlane formatted interchain message.
     * @return watchers The array of watcher addresses
     * @return threshold The number of watchers needed to mark an ISM as fraudulent
     */
    function watchersAndThreshold(
        bytes calldata _message
    ) external view returns (address[] memory, uint8);
}
