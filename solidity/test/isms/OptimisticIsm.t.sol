// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

// ============ External Imports ============
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Test.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../contracts/interfaces/IInterchainSecurityModule.sol";
import {StaticOptimisticIsm} from "../../contracts/isms/optimistic/StaticOptimisticIsm.sol";
import {StaticOptimisticIsmFactory} from "../../contracts/isms/optimistic/StaticOptimisticIsmFactory.sol";
import {OptimisticIsmErrors} from "../../contracts/isms/optimistic/OptimisticIsmErrors.sol";
import {TypeCasts} from "../../contracts/libs/TypeCasts.sol";
import {Message} from "../../contracts/libs/Message.sol";
import {TestIsm, MessageUtils, ThresholdTestUtils} from "./IsmTestUtils.sol";

contract OptimisticIsmTest is Test, OptimisticIsmErrors {
    using TypeCasts for bytes32;
    using Address for address;
    using Message for bytes;

    event PreVerified(bytes32 messageId, address submodule, uint256 timestamp);

    address private constant NON_OWNER =
        0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

    StaticOptimisticIsmFactory factory;
    StaticOptimisticIsm ism;

    function setUp() public {
        factory = new StaticOptimisticIsmFactory();
        deployMinimalStaticOptimisticIsm();
    }

    function deployMinimalStaticOptimisticIsm() public {
        StaticOptimisticIsm implementation = new StaticOptimisticIsm();
        bytes memory init = abi.encodeWithSelector(
            bytes4(keccak256("initialize(address)")),
            address(this)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), init);
        ism = StaticOptimisticIsm(address(proxy));
    }

    function deployStaticOptimisticIsm(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    )
        public
        returns (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        )
    {
        vm.assume(domain > numDomains);
        vm.assume(numWatchers >= threshold);
        uint32[] memory _domains = new uint32[](numDomains);
        submodules = new IInterchainSecurityModule[](numDomains);
        for (uint32 i; i < numDomains; ) {
            _domains[i] = domain - i;
            submodules[i] = deployTestIsm(bytes32(0));
            unchecked {
                ++i;
            }
        }
        watchers = setUpWatchers(numWatchers, seed);
        ism = factory.deploy(
            address(this),
            _domains,
            submodules,
            watchers,
            threshold,
            fraudWindow
        );
    }

    function setUpWatchers(
        uint8 n,
        bytes32 seed
    ) internal pure returns (address[] memory watchers) {
        bytes32 randomness = seed;
        watchers = new address[](n);
        for (uint256 i; i < n; ) {
            randomness = keccak256(abi.encode(randomness));
            watchers[i] = randomness.bytes32ToAddress();

            unchecked {
                ++i;
            }
        }
    }

    function deployTestIsm(
        bytes32 requiredMetadata
    ) internal returns (TestIsm) {
        return new TestIsm(abi.encode(requiredMetadata));
    }

    function testSetSubmodule(uint32 _domain) public {
        vm.expectRevert(NotContract.selector);
        ism.setSubmodule(_domain, IInterchainSecurityModule(address(1)));

        TestIsm _submodule = deployTestIsm(bytes32(0));

        vm.prank(NON_OWNER);
        vm.expectRevert("Ownable: caller is not the owner");
        ism.setSubmodule(_domain, _submodule);

        ism.setSubmodule(_domain, _submodule);
        assertEq(
            address(ism.submodule(MessageUtils.build(_domain))),
            address(_submodule)
        );
    }

    function testRemoveSubmodule(uint32 _domain) public {
        vm.expectRevert(
            abi.encodeWithSelector(OriginNotFound.selector, _domain)
        );
        ism.removeSubmodule(_domain);

        TestIsm _submodule = deployTestIsm(bytes32(0));
        ism.setSubmodule(_domain, _submodule);
        ism.removeSubmodule(_domain);
    }

    function testSetMultipleModules(
        uint8 numDomains,
        uint32 domain,
        uint256 fraudWindow
    ) public {
        vm.assume(0 < numDomains && numDomains < domain && domain < 10);
        (
            ,
            IInterchainSecurityModule[] memory expectedSubmodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                0,
                0,
                "",
                fraudWindow
            );

        for (uint32 i; i < numDomains; ) {
            assertEq(
                address(ism.submodule(MessageUtils.build(domain - i))),
                address(expectedSubmodules[i])
            );
            unchecked {
                ++i;
            }
        }
    }

    function testWatchersAndThreshold(uint8 m, uint8 n, bytes32 seed) public {
        vm.assume(0 < m && m <= n && n < 10);
        (address[] memory expectedWatchers, ) = deployStaticOptimisticIsm(
            0,
            1,
            m,
            n,
            seed,
            0
        );
        (address[] memory actualWatchers, uint8 actualThreshold) = ism
            .watchersAndThreshold("");
        assertEq(abi.encode(actualWatchers), abi.encode(expectedWatchers));
        assertEq(actualThreshold, m);
    }

    function testPreVerifyWithMinimalIsm(uint32 domain, bytes32 seed) public {
        vm.assume(domain > 0);

        TestIsm _submodule = deployTestIsm(seed);
        ism.setSubmodule(domain, _submodule);

        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.expectRevert(
            abi.encodeWithSelector(OriginNotFound.selector, domain - 1)
        );
        ism.preVerify(metadata, MessageUtils.build(domain - 1));
    }

    function testDeployOptimisticIsm(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );
        assertEq(submodules.length, numDomains);
        assertEq(watchers.length, numWatchers);
        assertTrue(numWatchers >= threshold);
    }

    function testPreVerify(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(threshold > 0);
        vm.assume(numDomains > 0);
        (
            ,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` coresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.expectRevert(AlreadyPreVerified.selector);
        ism.preVerify(metadata, MessageUtils.build(domain));
    }

    function testPreVerifyWithAlmostFraudulentISM(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(threshold > 0);
        vm.assume(numDomains > 0);
        (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` corresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        for (uint8 i; i < threshold - 1; ) {
            vm.prank(watchers[i]);
            ism.markFraudulent(address(_submodule));
            unchecked {
                ++i;
            }
        }
        assertFalse(ism.isFraudulentAt(address(_submodule), block.timestamp));
        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));
    }

    function testPreVerifyWithFraudulentISM(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(threshold > 0);
        vm.assume(numDomains > 0);
        (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` corresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();

        for (uint8 i; i < threshold; ) {
            vm.prank(watchers[i]);
            ism.markFraudulent(address(_submodule));
            unchecked {
                ++i;
            }
        }
        assertTrue(ism.isFraudulentAt(address(_submodule), block.timestamp));
        assertFalse(ism.preVerify(metadata, MessageUtils.build(domain)));
    }

    function testVerifyNonPreVerified(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(numDomains > 0);
        (
            ,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` coresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        assertFalse(ism.verify(metadata, message));
    }

    function testVerifyWithFraudWindow(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(numDomains > 0);
        vm.assume(fraudWindow > 0);
        vm.assume(fraudWindow < 1 days);
        (
            ,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` coresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));

        assertFalse(ism.verify(metadata, message));

        vm.warp(block.timestamp + fraudWindow - 1);
        assertFalse(ism.verify(metadata, message));

        vm.warp(block.timestamp + fraudWindow);
        assertTrue(ism.verify(metadata, message));
    }

    function testVerifyWithFraudulentISM(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(threshold > 0);
        vm.assume(numDomains > 0);
        vm.assume(fraudWindow > 0);
        vm.assume(fraudWindow < 1 days);
        (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` coresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.warp(block.timestamp + fraudWindow / 2);
        for (uint8 i; i < threshold; ) {
            vm.prank(watchers[i]);
            ism.markFraudulent(address(_submodule));
            unchecked {
                ++i;
            }
        }

        vm.warp(block.timestamp + fraudWindow);
        assertFalse(ism.verify(metadata, message));
    }

    function testVerify(
        uint8 numDomains,
        uint32 domain,
        uint8 threshold,
        uint8 numWatchers,
        bytes32 seed,
        uint256 fraudWindow
    ) public {
        vm.assume(threshold > 0);
        vm.assume(numDomains > 0);
        vm.assume(fraudWindow > 0);
        vm.assume(fraudWindow < 1 days);
        (
            address[] memory watchers,
            IInterchainSecurityModule[] memory submodules
        ) = deployStaticOptimisticIsm(
                numDomains,
                domain,
                threshold,
                numWatchers,
                seed,
                fraudWindow
            );

        /// @dev `submodules[0]` coresponds to the `domain`.
        TestIsm _submodule = TestIsm(address(submodules[0]));
        bytes memory metadata = _submodule.requiredMetadata();
        bytes memory message = MessageUtils.build(domain);

        vm.expectEmit(address(ism));
        emit PreVerified(message.id(), address(_submodule), block.timestamp);
        assertTrue(ism.preVerify(metadata, message));

        vm.warp(block.timestamp + fraudWindow / 2);
        for (uint8 i; i < threshold - 1; ) {
            vm.prank(watchers[i]);
            ism.markFraudulent(address(_submodule));
            unchecked {
                ++i;
            }
        }

        vm.warp(block.timestamp + fraudWindow);
        assertTrue(ism.verify(metadata, message));
    }
}
