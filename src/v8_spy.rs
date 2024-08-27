
use anyhow::{Context, Result};
use spytools::ProcessInfo;

use remoteprocess::{Pid, Process, ProcessMemory};

struct Version {
    major: u32,
    minor: u32,
    build: u32,
    patch: u32,
}

#[derive(Default, Debug)]
struct VMData {
    fixed: Fixed,
    frame_pointer: FramePointer,
    scope_info_index: ScopeInfoIndex,
    deoptimization_data_index: DeoptimizationDataIndex,
    code_kind: CodeKind,
    frame_type: FrameType,
    typ: Type,
    heap_object: HeapObject,
    map: Map,
    fixed_array_base: FixedArrayBase,
    fixed_array: FixedArray,
    string: String,
    seq_one_byte_string: SeqOneByteString,
    seq_two_byte_string: SeqTwoByteString,
    cons_string: ConsString,
    thin_string: ThinString,
    jsfunction: JSFunction,
    code: Code,
    shared_function_info: SharedFunctionInfo,
    baseline_data: BaselineData,
    bytecode_array: BytecodeArray,
    scope_info: ScopeInfo,
    deoptimization_literal_array: DeoptimizationLiteralArray,
    script: Script,
}

#[derive(Default, Debug)]
struct Fixed {
    heap_object_tag_mask: u32,
    smi_tag_mask: u32,
    heap_object_tag: u16,
    smi_tag: u16,
    smi_shift_size: u16,
    first_nonstring_type: u16,
    string_encoding_mask: u16,
    string_representation_mask: u16,
    seq_string_tag: u16,
    cons_string_tag: u16,
    one_byte_string_tag: u16,
    two_byte_string_tag: u16,
    sliced_string_tag: u16,
    thin_string_tag: u16,
    first_jsfunction_type: u16,
    last_jsfunction_type: u16,
}

#[derive(Default, Debug)]
struct FramePointer {
    function: u8,
    context: u8,
    bytecode_array: u8,
    bytecode_offset: u8,
}

#[derive(Default, Debug)]
struct ScopeInfoIndex {
    first_vars: u8,
    ncontext_locals: u8,
}

#[derive(Default, Debug)]
struct DeoptimizationDataIndex {
    inlined_function_count: u8,
    literal_array: u8,
    shared_function_info: u8,
    inlining_positions: u8,
}

#[derive(Default, Debug)]
struct CodeKind {
    field_mask: u32,
    field_shift: u8,
    baseline: u8,
}

#[derive(Default, Debug)]
struct FrameType {
    arguments_adaptor_frame: u8,
    baseline_frame: u8,
    builtin_continuation_frame: u8,
    builtin_exit_frame: u8,
    builtin_frame: u8,
    cwasm_entry_frame: u8,
    construct_entry_frame: u8,
    construct_frame: u8,
    entry_frame: u8,
    exit_frame: u8,
    internal_frame: u8,
    interpreted_frame: u8,
    java_script_builtin_continuation_frame: u8,
    java_script_builtin_continuation_with_catch_frame: u8,
    java_script_frame: u8,
    js_to_wasm_frame: u8,
    native_frame: u8,
    optimized_frame: u8,
    stub_frame: u8,
    wasm_compile_lazy_frame: u8,
    wasm_compiled_frame: u8,
    wasm_exit_frame: u8,
    wasm_interpreter_entry_frame: u8,
    wasm_to_js_frame: u8,
}

#[derive(Default, Debug)]
struct Type {
    baseline_data: u16,
    byte_array: u16,
    bytecode_array: u16,
    code: u16,
    fixed_array: u16,
    weak_fixed_array: u16,
    js_function: u16,
    map: u16,
    script: u16,
    scope_info: u16,
    shared_function_info: u16,
}

#[derive(Default, Debug)]
struct HeapObject {
    map: u16,
}

#[derive(Default, Debug)]
struct Map {
    instance_type: u16,
}

#[derive(Default, Debug)]
struct FixedArrayBase {
    length: u16,
}

#[derive(Default, Debug)]
struct FixedArray {
    data: u16,
}

#[derive(Default, Debug)]
struct String {
    length: u16,
}

#[derive(Default, Debug)]
struct SeqOneByteString {
    chars: u16,
}

#[derive(Default, Debug)]
struct SeqTwoByteString {
    chars: u16,
}

#[derive(Default, Debug)]
struct ConsString {
    first: u16,
    second: u16,
}

#[derive(Default, Debug)]
struct ThinString {
    actual: u16,
}

#[derive(Default, Debug)]
struct JSFunction {
    code: u16,
    shared_function_info: u16,
}

#[derive(Default, Debug)]
struct Code {
    deoptimization_data: u16,
    source_position_table: u16,
    instruction_start: u16,
    instruction_size: u16,
    flags: u16,
}

#[derive(Default, Debug)]
struct SharedFunctionInfo {
    name_or_scope_info: u16,
    function_data: u16,
    script_or_debug_info: u16,
}

#[derive(Default, Debug)]
struct BaselineData {
    data: u16,
}

#[derive(Default, Debug)]
struct BytecodeArray {
    source_position_table: u16,
    data: u16,
}

#[derive(Default, Debug)]
struct ScopeInfo {
    heap_object: bool,
}

#[derive(Default, Debug)]
struct DeoptimizationLiteralArray {
    weak_fixed_array: bool,
}

#[derive(Default, Debug)]
struct Script {
    name: u16,
    line_ends: u16,
    source: u16,
}

pub struct V8Spy {
    pub pid: Pid,
    pub process: Process,
    pub version: Version,
}

impl V8Spy {
    pub fn new(pid: Pid) -> Result<Self> {
        let process = remoteprocess::Process::new(pid)
            .context(format!("Failed to open process {} - check if it is running.", pid))?;

        let process_info = ProcessInfo::new::<spytools::process::NodeProcessType>(&process)?;

        // lock the process when loading up on freebsd (rather than locking
        // on every memory read). Needs done after getting python process info
        // because procmaps also tries to attach w/ ptrace on freebsd
        #[cfg(target_os = "freebsd")]
        let _lock = process.lock();

        let version = get_v8_version(&process_info, &process);
        println!("v8 version: {}.{}.{}.{}", version.major, version.minor, version.build, version.patch);

        let v8_data = get_v8_data(&process_info, &process);
        println!("{:?}", v8_data);

        Ok(Self { pid, process, version })
    }
}

fn get_v8_data(process_info: &ProcessInfo, process: &Process) -> VMData {
    let mut data = VMData::default();
    read_memory(process_info, process, "v8dbg_HeapObjectTagMask", &mut data.fixed.heap_object_tag_mask);
    read_memory(process_info, process, "v8dbg_SmiTagMask", &mut data.fixed.smi_tag_mask);
    read_memory(process_info, process, "v8dbg_HeapObjectTag", &mut data.fixed.heap_object_tag);
    read_memory(process_info, process, "v8dbg_SmiTag", &mut data.fixed.smi_tag);
    read_memory(process_info, process, "v8dbg_SmiShiftSize", &mut data.fixed.smi_shift_size);
    read_memory(process_info, process, "v8dbg_FirstNonstringType", &mut data.fixed.first_nonstring_type);
    read_memory(process_info, process, "v8dbg_StringEncodingMask", &mut data.fixed.string_encoding_mask);
    read_memory(process_info, process, "v8dbg_StringRepresentationMask", &mut data.fixed.string_representation_mask);
    read_memory(process_info, process, "v8dbg_SeqStringTag", &mut data.fixed.seq_string_tag);
    read_memory(process_info, process, "v8dbg_ConsStringTag", &mut data.fixed.cons_string_tag);
    read_memory(process_info, process, "v8dbg_OneByteStringTag", &mut data.fixed.one_byte_string_tag);
    read_memory(process_info, process, "v8dbg_TwoByteStringTag", &mut data.fixed.two_byte_string_tag);
    read_memory(process_info, process, "v8dbg_SlicedStringTag", &mut data.fixed.sliced_string_tag);
    read_memory(process_info, process, "v8dbg_ThinStringTag", &mut data.fixed.thin_string_tag);
    read_memory(process_info, process, "v8dbg_FirstJSFunctionType", &mut data.fixed.first_jsfunction_type);
    read_memory(process_info, process, "v8dbg_LastJSFunctionType", &mut data.fixed.last_jsfunction_type);
    read_memory(process_info, process, "v8dbg_off_fp_function", &mut data.frame_pointer.function);
    read_memory(process_info, process, "v8dbg_off_fp_context", &mut data.frame_pointer.context);
    read_memory(process_info, process, "v8dbg_off_fp_bytecode_array", &mut data.frame_pointer.bytecode_array);
    read_memory(process_info, process, "v8dbg_off_fp_bytecode_offset", &mut data.frame_pointer.bytecode_offset);
    read_memory(process_info, process, "v8dbg_scopeinfo_idx_first_vars", &mut data.scope_info_index.first_vars);
    read_memory(process_info, process, "v8dbg_scopeinfo_idx_ncontextlocals", &mut data.scope_info_index.ncontext_locals);
    read_memory(process_info, process, "v8dbg_DeoptimizationDataInlinedFunctionCountIndex", &mut data.deoptimization_data_index.inlined_function_count);
    read_memory(process_info, process, "v8dbg_DeoptimizationDataLiteralArrayIndex", &mut data.deoptimization_data_index.literal_array);
    read_memory(process_info, process, "v8dbg_DeoptimizationDataSharedFunctionInfoIndex", &mut data.deoptimization_data_index.shared_function_info);
    read_memory(process_info, process, "v8dbg_DeoptimizationDataInliningPositionsIndex", &mut data.deoptimization_data_index.inlining_positions);
    read_memory(process_info, process, "v8dbg_CodeKindFieldMask", &mut data.code_kind.field_mask);
    read_memory(process_info, process, "v8dbg_CodeKindFieldShift", &mut data.code_kind.field_shift);
    read_memory(process_info, process, "v8dbg_CodeKindBaseline", &mut data.code_kind.baseline);
    read_memory(process_info, process, "v8dbg_frametype_ArgumentsAdaptorFrame", &mut data.frame_type.arguments_adaptor_frame);
    read_memory(process_info, process, "v8dbg_frametype_BaselineFrame", &mut data.frame_type.baseline_frame);
    read_memory(process_info, process, "v8dbg_frametype_BuiltinContinuationFrame", &mut data.frame_type.builtin_continuation_frame);
    read_memory(process_info, process, "v8dbg_frametype_BuiltinExitFrame", &mut data.frame_type.builtin_exit_frame);
    read_memory(process_info, process, "v8dbg_frametype_BuiltinFrame", &mut data.frame_type.builtin_frame);
    read_memory(process_info, process, "v8dbg_frametype_CwasmEntryFrame", &mut data.frame_type.cwasm_entry_frame);
    read_memory(process_info, process, "v8dbg_frametype_ConstructEntryFrame", &mut data.frame_type.construct_entry_frame);
    read_memory(process_info, process, "v8dbg_frametype_ConstructFrame", &mut data.frame_type.construct_frame);
    read_memory(process_info, process, "v8dbg_frametype_EntryFrame", &mut data.frame_type.entry_frame);
    read_memory(process_info, process, "v8dbg_frametype_ExitFrame", &mut data.frame_type.exit_frame);
    read_memory(process_info, process, "v8dbg_frametype_InternalFrame", &mut data.frame_type.internal_frame);
    read_memory(process_info, process, "v8dbg_frametype_InterpretedFrame", &mut data.frame_type.interpreted_frame);
    read_memory(process_info, process, "v8dbg_frametype_JavaScriptBuiltinContinuationFrame", &mut data.frame_type.java_script_builtin_continuation_frame);
    read_memory(process_info, process, "v8dbg_frametype_JavaScriptBuiltinContinuationWithCatchFrame", &mut data.frame_type.java_script_builtin_continuation_with_catch_frame);
    read_memory(process_info, process, "v8dbg_frametype_JavaScriptFrame", &mut data.frame_type.java_script_frame);
    read_memory(process_info, process, "v8dbg_frametype_JsToWasmFrame", &mut data.frame_type.js_to_wasm_frame);
    read_memory(process_info, process, "v8dbg_frametype_NativeFrame", &mut data.frame_type.native_frame);
    read_memory(process_info, process, "v8dbg_frametype_OptimizedFrame", &mut data.frame_type.optimized_frame);
    read_memory(process_info, process, "v8dbg_frametype_StubFrame", &mut data.frame_type.stub_frame);
    read_memory(process_info, process, "v8dbg_frametype_WasmCompileLazyFrame", &mut data.frame_type.wasm_compile_lazy_frame);
    read_memory(process_info, process, "v8dbg_frametype_WasmCompiledFrame", &mut data.frame_type.wasm_compiled_frame);
    read_memory(process_info, process, "v8dbg_frametype_WasmExitFrame", &mut data.frame_type.wasm_exit_frame);
    read_memory(process_info, process, "v8dbg_frametype_WasmInterpreterEntryFrame", &mut data.frame_type.wasm_interpreter_entry_frame);
    read_memory(process_info, process, "v8dbg_frametype_WasmToJsFrame", &mut data.frame_type.wasm_to_js_frame);
    read_memory(process_info, process, "v8dbg_type_BaselineData__BASELINE_DATA_TYPE", &mut data.baseline_data.data);
    read_memory(process_info, process, "v8dbg_type_ByteArray__BYTE_ARRAY_TYPE", &mut data.typ.byte_array);
    read_memory(process_info, process, "v8dbg_type_BytecodeArray__BYTECODE_ARRAY_TYPE", &mut data.typ.bytecode_array);
    read_memory(process_info, process, "v8dbg_type_Code__CODE_TYPE", &mut data.typ.code);
    read_memory(process_info, process, "v8dbg_type_FixedArray__FIXED_ARRAY_TYPE", &mut data.typ.fixed_array);
    read_memory(process_info, process, "v8dbg_type_WeakFixedArray__WEAK_FIXED_ARRAY_TYPE", &mut data.typ.weak_fixed_array);
    read_memory(process_info, process, "v8dbg_type_JSFunction__JS_FUNCTION_TYPE", &mut data.typ.js_function);
    read_memory(process_info, process, "v8dbg_type_Map__MAP_TYPE", &mut data.typ.map);
    read_memory(process_info, process, "v8dbg_type_Script__SCRIPT_TYPE", &mut data.typ.script);
    read_memory(process_info, process, "v8dbg_type_ScopeInfo__SCOPE_INFO_TYPE", &mut data.typ.scope_info);
    read_memory(process_info, process, "v8dbg_type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE", &mut data.typ.shared_function_info);
    read_memory(process_info, process, "v8dbg_class_HeapObject__map__Map", &mut data.heap_object.map);
    read_memory(process_info, process, "v8dbg_class_Map__instance_type__uint16_t", &mut data.map.instance_type);
    read_memory(process_info, process, "v8dbg_class_FixedArrayBase__length__SMI", &mut data.fixed_array_base.length);
    read_memory(process_info, process, "v8dbg_class_FixedArray__data__uintptr_t", &mut data.fixed_array.data);
    read_memory(process_info, process, "v8dbg_class_String__length__int32_t", &mut data.string.length);
    read_memory(process_info, process, "v8dbg_class_SeqOneByteString__chars__char", &mut data.seq_one_byte_string.chars);
    read_memory(process_info, process, "v8dbg_class_SeqTwoByteString__chars__char", &mut data.seq_two_byte_string.chars);
    read_memory(process_info, process, "v8dbg_class_ConsString__first__String", &mut data.cons_string.first);
    read_memory(process_info, process, "v8dbg_class_ConsString__second__String", &mut data.cons_string.second);
    read_memory(process_info, process, "v8dbg_class_ThinString__actual__String", &mut data.thin_string.actual);
    return data;
}

fn read_memory<T>(process_info: &ProcessInfo, process: &Process, symbol: &str, data: &mut T) {
    let addr = process_info.get_symbol(symbol);
    if addr.is_none() {
        println!("Failed to get symbol {}", symbol);
        return;
    }
    let addr = addr.unwrap();

    let size = match std::any::type_name::<T>() {
        "u32" => 4,
        "u16" => 2,
        "u8" => 1,
        _ => panic!("Unsupported type"),
    };

    let mut buf = vec![0u8; size];

    if let Ok(()) = process.read(*addr as usize, &mut buf) {
        unsafe {
            let data_ptr: *mut T = data as *mut T;
            std::ptr::copy_nonoverlapping(buf.as_ptr(), data_ptr as *mut u8, size);
        }
        return;
    }
    panic!("Failed to read memory for symbol {}", symbol);
}

fn get_v8_version(process_info: &ProcessInfo, process: &Process) -> Version {
    let mut version = [0u32; 4];
    for (i, ver) in ["major", "minor", "build", "patch"].iter().enumerate() {
        let symbol = format!("_ZN2v88internal7Version6{}_E", ver);
        let symbol = process_info.get_symbol(symbol.as_str()).unwrap();
        let mut buf = [0u8; 4];
        if let Ok(()) = process.read(*symbol as usize, &mut buf) {
            version[i] = buf[0] as u32 | (buf[1] as u32) << 8 | (buf[2] as u32) << 16 | (buf[3] as u32) << 24;
        } else {
            println!("Failed to read memory for symbol {}", ver);
        }
    }
    Version {
        major: version[0],
        minor: version[1],
        build: version[2],
        patch: version[3],
    }
}