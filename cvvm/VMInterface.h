
#pragma once

#include <memory>
#include <libdevcore/Exceptions.h>
#include "ExtVMFace.h"

namespace dev
{
namespace eth
{

struct VMException: virtual Exception {};
#define ETH_SIMPLE_EXCEPTION_VM(X) struct X: virtual VMException { const char* what() const noexcept override { return #X; } }
ETH_SIMPLE_EXCEPTION_VM(BreakPointHit);
ETH_SIMPLE_EXCEPTION_VM(BadInstruction);
ETH_SIMPLE_EXCEPTION_VM(BadJumpDestination);
ETH_SIMPLE_EXCEPTION_VM(OutOfGas);
ETH_SIMPLE_EXCEPTION_VM(OutOfStack);
ETH_SIMPLE_EXCEPTION_VM(StackUnderflow);

/// CVVM Virtual Machine interface
class VMInterface
{
public:
	VMInterface() = default;
	virtual ~VMInterface() = default;
	VMInterface(VMInterface const&) = delete;
	VMInterface& operator=(VMInterface const&) = delete;

	
	void exec(u256& io_gas, ExtVMFace& _ext, bytesRef _out, OnOpFunc const& _onOp = {})
	{
		execImpl(io_gas, _ext, _onOp).copyTo(_out);
	}

	bytes exec(u256& io_gas, ExtVMFace& _ext, OnOpFunc const& _onOp = {})
	{
		return execImpl(io_gas, _ext, _onOp).toVector();
	}

	/// CVVM implementation
	virtual bytesConstRef execImpl(u256& io_gas, ExtVMFace& _ext, OnOpFunc const& _onOp) = 0;
};

}
}
