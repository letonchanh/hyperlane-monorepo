// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

/**
 * @title OptimisticIsmErrors
 * @notice Custom errors for Optimistic ISM.
 */
contract OptimisticIsmErrors {
    error ZeroAddress();
    error LengthMismatch();
    error UnauthorizedWatcher();
    error NotContract();
    error OriginNotFound(uint32 origin);
    error AlreadyPreVerified();
    error AlreadyFlaggedAsFraud();
    error AlreadyMarkedFraudulent();
}
