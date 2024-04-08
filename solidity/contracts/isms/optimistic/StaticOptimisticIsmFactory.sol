// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ========== External Imports ==========
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {StaticOptimisticIsm} from "./StaticOptimisticIsm.sol";
import {StaticThresholdAddressSetFactory} from "../../libs/StaticAddressSetFactory.sol";

contract StaticOptimisticIsmFactory is StaticThresholdAddressSetFactory {
    function _deployImplementation()
        internal
        virtual
        override
        returns (address)
    {
        return address(new StaticOptimisticIsm());
    }

    /**
     * @notice Deploys and initializes a StaticOptimisticIsm.
     * @param _owner The owner to set on the ISM.
     * @param _domains The origin domains.
     * @param _submodules The ISMs to use to pre-verify messages.
     * @param _watchers The watchers to set on the ISM.
     * @param _threshold The number of ISMs needed to mark a submodule as fraudulent.
     * @param _fraudWindow The fraud window in seconds.
     */
    function deploy(
        address _owner,
        uint32[] calldata _domains,
        IInterchainSecurityModule[] calldata _submodules,
        address[] calldata _watchers,
        uint8 _threshold,
        uint256 _fraudWindow
    ) external returns (StaticOptimisticIsm) {
        StaticOptimisticIsm impl = StaticOptimisticIsm(
            deploy(_watchers, _threshold)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
        StaticOptimisticIsm ism = StaticOptimisticIsm(address(proxy));
        ism.initialize(_owner, _domains, _submodules, _fraudWindow);
        return ism;
    }
}
