#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use verrev_capability::Capability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeError {
    ModuleLoadFailed,
    InstantiationFailed,
    CapabilityDenied,
    ExecutionTimeout,
    OutOfMemory,
    UnsupportedExecution,
}

pub type Result<T> = core::result::Result<T, RuntimeError>;

pub struct WasmModule {
    bytecode: Vec<u8>,
}

pub struct Instance {
    module: WasmModule,
    capabilities: Vec<Capability>,
    memory: Option<Vec<u8>>,
}

impl WasmModule {
    /// Parses the WebAssembly container header and takes ownership of its bytes.
    /// This does not validate sections or produce executable code.
    pub fn parse(wasm: &[u8]) -> Result<Self> {
        Self::validate_header(wasm)?;
        Ok(WasmModule {
            bytecode: wasm.to_vec(),
        })
    }

    /// Compilation is not implemented; a valid header is not executable proof.
    pub fn compile(wasm: &[u8]) -> Result<Self> {
        Self::validate_header(wasm)?;
        Err(RuntimeError::UnsupportedExecution)
    }

    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    pub fn instantiate(&self, capabilities: &[Capability]) -> Result<Instance> {
        let _ = (self, capabilities);
        Err(RuntimeError::UnsupportedExecution)
    }

    fn validate_header(wasm: &[u8]) -> Result<()> {
        if wasm.len() < 8 || wasm[..4] != *b"\0asm" {
            return Err(RuntimeError::ModuleLoadFailed);
        }
        let version = u32::from_le_bytes([wasm[4], wasm[5], wasm[6], wasm[7]]);
        if version != 1 {
            return Err(RuntimeError::ModuleLoadFailed);
        }
        Ok(())
    }
}

impl Instance {
    pub fn call(&mut self, function: &str, args: &[u8]) -> Result<Vec<u8>> {
        let _ = (function, args);
        Err(RuntimeError::UnsupportedExecution)
    }

    pub fn bytecode(&self) -> &[u8] {
        self.module.bytecode()
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn memory(&self) -> Option<&[u8]> {
        self.memory.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_MODULE: &[u8] = b"\0asm\x01\0\0\0";

    #[test]
    fn parse_owns_module_bytes() {
        let mut bytes = EMPTY_MODULE.to_vec();
        let module = WasmModule::parse(&bytes);
        assert!(module.is_ok());
        let module = match module {
            Ok(module) => module,
            Err(error) => panic!("valid header rejected: {error:?}"),
        };
        bytes.fill(0);

        assert_eq!(module.bytecode(), EMPTY_MODULE);
    }

    #[test]
    fn parse_rejects_invalid_headers() {
        for invalid in [
            &b""[..],
            &b"\0asm\x01\0\0"[..],
            &b"not wasm"[..],
            &b"\0asm\x02\0\0\0"[..],
        ] {
            assert_eq!(
                WasmModule::parse(invalid).err(),
                Some(RuntimeError::ModuleLoadFailed)
            );
        }
    }

    #[test]
    fn compilation_and_instantiation_do_not_claim_execution_support() {
        assert!(matches!(
            WasmModule::compile(EMPTY_MODULE),
            Err(RuntimeError::UnsupportedExecution)
        ));
        let module = match WasmModule::parse(EMPTY_MODULE) {
            Ok(module) => module,
            Err(error) => panic!("valid header rejected: {error:?}"),
        };
        assert_eq!(
            module.instantiate(&[]).err(),
            Some(RuntimeError::UnsupportedExecution)
        );
    }

    #[test]
    fn calls_return_an_explicit_unsupported_execution_error() {
        let module = match WasmModule::parse(EMPTY_MODULE) {
            Ok(module) => module,
            Err(error) => panic!("valid header rejected: {error:?}"),
        };
        let mut instance = Instance {
            module,
            capabilities: Vec::new(),
            memory: None,
        };

        assert_eq!(
            instance.call("main", b"arguments").err(),
            Some(RuntimeError::UnsupportedExecution)
        );
        assert_eq!(instance.bytecode(), EMPTY_MODULE);
        assert!(instance.capabilities().is_empty());
        assert_eq!(instance.memory(), None);
    }
}
