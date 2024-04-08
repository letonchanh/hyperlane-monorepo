// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {AbstractOptimisticIsm} from "./AbstractOptimisticIsm.sol";
import {Message} from "../../libs/Message.sol";
import {MetaProxy} from "../../libs/MetaProxy.sol";
import {TypeCasts} from "../../libs/TypeCasts.sol";
import {EnumerableMapExtended} from "../../libs/EnumerableMapExtended.sol";

contract StaticOptimisticIsm is AbstractOptimisticIsm, OwnableUpgradeable {
    using Message for bytes;
    using Address for address;
    using TypeCasts for bytes32;
    using TypeCasts for address;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMapExtended for EnumerableMapExtended.UintToBytes32Map;

    // ============ State Variables ============

    /// @notice The threshold for marking the ISM submodule as fraudulent.
    uint8 internal threshold;

    /// @notice The constant representing the active state of a watcher.
    uint8 internal constant INACTIVE_WATCHER = 1;

    /// @notice The constant representing the inactive state of a watcher.
    uint8 internal constant ACTIVE_WATCHER = 2;

    /// @notice The fraud window in seconds.
    /// @dev The fraud window is configurable by the owner of the OptimisticIsm.
    uint256 internal _fraudWindow;

    /// @notice The submodules responsible for pre-verifying messages.
    /// @dev The submodules are configurable by the owner of the OptimisticIsm.
    EnumerableMapExtended.UintToBytes32Map internal _submodules;

    /// @notice Time at which the ISM submodule is flagged
    /// as fraudulent by m-of-n watchers.
    mapping(address => uint256) internal _submoduleFlaggedTime;

    /// @notice A mapping from the ISM submodule to a set of
    /// watchers that marked the ISM as fraudulent.
    mapping(address => EnumerableSet.AddressSet)
        internal _submoduleMarkedFraudulentBy;

    /// @notice The watchers responsible for marking
    /// the ISM submodule as fraudulent.
    EnumerableSet.AddressSet watchers;

    // ============ Modifiers ============

    /// @notice Ensures that the caller is an active watcher.
    modifier onlyWatcher() {
        if (!watchers.contains(msg.sender)) revert UnauthorizedWatcher();
        _;
    }

    // ============ Initializer ============

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the OptimisticIsm with the owner.
     * @param _owner The owner of the contract.
     */
    function initialize(address _owner) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
    }

    /**
     * @notice Initializes the OptimisticIsm with the owner,
     * the ISM submodule, and the fraud window.
     * @param _owner The owner of the contract.
     * @param _domains The origin domains
     * @param __submodules The ISMs to use to pre-verify messages.
     * @param __fraudWindow The fraud window in seconds.
     */
    function initialize(
        address _owner,
        uint32[] calldata _domains,
        IInterchainSecurityModule[] calldata __submodules,
        uint256 __fraudWindow
    ) public initializer {
        __Ownable_init();
        _fraudWindow = __fraudWindow;
        if (_domains.length != __submodules.length) revert LengthMismatch();
        uint256 numSubmodules = __submodules.length;
        for (uint256 i; i < numSubmodules; ) {
            _set(_domains[i], address(__submodules[i]));
            unchecked {
                ++i;
            }
        }
        (address[] memory _watchers, uint8 _threshold) = abi.decode(
            MetaProxy.metadata(),
            (address[], uint8)
        );
        threshold = _threshold;
        uint256 numWatchers = _watchers.length;
        for (uint256 i; i < numWatchers; ) {
            watchers.add(_watchers[i]);
            unchecked {
                ++i;
            }
        }
        _transferOwnership(_owner);
    }

    // ============ Internal Functions ============
    /**
     * @notice Sets the ISM to be used for the specified origin domain
     * @param _domain The origin domain
     * @param _submodule The ISM to use to verify messages in the domain.
     */
    function _set(uint32 _domain, address _submodule) internal {
        if (!_submodule.isContract()) revert NotContract();
        _submodules.set(_domain, _submodule.addressToBytes32());
    }

    // ============ External Functions ============

    /**
     * @notice Sets the ISM submodule to be used for pre-verifying messages.
     * @param _submodule The ISM to use to pre-verify messages.
     */
    function setSubmodule(
        uint32 _domain,
        IInterchainSecurityModule _submodule
    ) external onlyOwner {
        _set(_domain, address(_submodule));
    }

    /**
     * @notice Removes the specified origin domain.
     * @param _domain The origin domain.
     */
    function removeSubmodule(uint32 _domain) external onlyOwner {
        bool found = _submodules.remove(_domain);
        if (!found) revert OriginNotFound(_domain);
    }

    /**
     * @notice Sets the fraud window in seconds.
     * @param __fraudWindow The fraud window in seconds.
     */
    function setFraudWindow(uint256 __fraudWindow) external onlyOwner {
        _fraudWindow = __fraudWindow;
    }

    /**
     * @notice Adds a watcher to the set of watchers.
     * @param _watcher The address of the watcher to add.
     */
    function addWatcher(address _watcher) external onlyOwner {
        if (_watcher != address(0)) revert ZeroAddress();
        watchers.add(_watcher);
    }

    /**
     * @notice Removes a watcher from the set of watchers.
     * @param _watcher The address of the watcher to remove.
     */
    function removeWatcher(address _watcher) external onlyOwner {
        watchers.remove(_watcher);
    }

    /// @inheritdoc IOptimisticIsm
    function markFraudulent(address _submodule) external override onlyWatcher {
        if (_submoduleFlaggedTime[_submodule] != 0)
            revert AlreadyFlaggedAsFraud();

        if (_submoduleMarkedFraudulentBy[_submodule].contains(msg.sender))
            revert AlreadyMarkedFraudulent();

        if (
            _submoduleMarkedFraudulentBy[_submodule].length() == threshold - 1
        ) {
            _submoduleFlaggedTime[_submodule] = block.timestamp;
        } else {
            _submoduleMarkedFraudulentBy[_submodule].add(msg.sender);
        }
    }

    // ============ Public Functions ============

    /// @inheritdoc AbstractOptimisticIsm
    function fraudWindow(
        bytes calldata /* _message */
    ) public view override returns (uint256) {
        return _fraudWindow;
    }

    /// @inheritdoc AbstractOptimisticIsm
    function isFraudulentAt(
        address _submodule,
        uint256 _timestamp
    ) public view override returns (bool) {
        uint256 flaggedTime = _submoduleFlaggedTime[_submodule];
        return flaggedTime != 0 && flaggedTime <= _timestamp;
    }

    /// @inheritdoc IOptimisticIsm
    function submodule(
        bytes calldata _message
    ) public view override returns (IInterchainSecurityModule) {
        uint32 _origin = _message.origin();
        (bool contained, bytes32 _module) = _submodules.tryGet(_origin);
        if (!contained) revert OriginNotFound(_origin);
        return IInterchainSecurityModule(_module.bytes32ToAddress());
    }

    /// @inheritdoc IOptimisticIsm
    /// @dev In StaticOptimisticIsm, the set of watchers and the
    /// threshold are fixed and can be set only during the
    /// initialization.
    function watchersAndThreshold(
        bytes calldata /* _message */
    ) public pure override returns (address[] memory, uint8) {
        return abi.decode(MetaProxy.metadata(), (address[], uint8));
    }
}
