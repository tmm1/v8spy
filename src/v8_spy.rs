
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

        let mut vms = get_v8_data(&process_info, &process);
        println!("{:?}", vms);

        let ver = v8_ver(version.major, version.minor, version.build);
        let pointer_size = 8;

        // Add some defaults when needed
        if vms.frame_pointer.bytecode_array == 0 {
            // Not available before V8 9.5.2
            if ver >= v8_ver(8, 7, 198) {
                vms.frame_pointer.bytecode_array = vms.frame_pointer.function - 2 * pointer_size;
            } else {
                vms.frame_pointer.bytecode_array = vms.frame_pointer.function - 1 * pointer_size;
            }
        }
        if vms.frame_pointer.bytecode_offset == 0 {
            // Not available before V8 9.5.2
            vms.frame_pointer.bytecode_offset = vms.frame_pointer.bytecode_array - pointer_size;
        }
        if vms.fixed.first_jsfunction_type == 0 {
            // Since V8 9.0.14 the JSFunction is no longer a final class, but has several
            // classes inheriting form it. The only way to check for the inheritance is to
            // know which InstaceType tags belong to the range.
            let mut num_jsfunc_types = 1u16;
            if ver >= v8_ver(9, 6, 138) {
                // Class constructor special case
                num_jsfunc_types = 15;
            } else if ver >= v8_ver(9, 0, 14) {
                // Several constructor special cases added
                num_jsfunc_types = 14;
            }
            vms.fixed.first_jsfunction_type = vms.typ.js_function;
            vms.fixed.last_jsfunction_type = vms.fixed.first_jsfunction_type + num_jsfunc_types - 1;
        }
        if vms.jsfunction.code == 0 {
            if ver >= v8_ver(11, 7, 368) {
                vms.jsfunction.code = vms.jsfunction.shared_function_info - pointer_size as u16;
            } else {
                // At least back to V8 8.4
                vms.jsfunction.code = vms.jsfunction.shared_function_info + 3 * pointer_size as u16;
            }
        }
        if vms.code.instruction_size != 0 {
            if vms.code.source_position_table == 0 {
                // At least back to V8 8.4
                vms.code.source_position_table = vms.code.instruction_size - 2 * pointer_size as u16;
            }
            if vms.code.flags == 0 {
                // Back to V8 8.8.172
                vms.code.flags = vms.code.instruction_size + 2 * 4; // 2 * sizeof(int)
            }
        } else if vms.code.source_position_table != 0 {
            // Likely V8 11.x where the Code postmortem data was accidentally deleted
            if vms.code.deoptimization_data == 0 {
                vms.code.deoptimization_data = vms.code.source_position_table - pointer_size as u16;
            }
            if vms.code.instruction_start == 0 {
                vms.code.instruction_start = vms.code.source_position_table + 2 * pointer_size as u16;
            }
            if vms.code.flags == 0 {
                vms.code.flags = vms.code.instruction_start + pointer_size as u16;
            }
            if vms.code.instruction_size == 0 {
                vms.code.instruction_size = vms.code.flags + 4;
                if ver >= v8_ver(11, 4, 59) {
                    // V8 starting 11.1.x Code has kBuiltinIdOffset and kKindSpecificFlagsOffset
                    // which changed again in 11.4.59 when these were removed in commit
                    // cb8be519f0add9b7 "[code] Merge kind_specific_flags with flags"
                    vms.code.instruction_size += 2 + 2;
                }
            }
        }
        if vms.code.deoptimization_data == 0 && vms.code.source_position_table != 0 {
            // Used unconditionally, pending patch for V8 to export this
            // At least back to V8 7.2
            vms.code.deoptimization_data = vms.code.source_position_table - pointer_size as u16;
        }
        if vms.script.source == 0 {
            // At least back to V8 8.4
            vms.script.source = vms.script.name - pointer_size as u16;
        }
        if vms.bytecode_array.source_position_table == 0 {
            // Lost in V8 9.4
            vms.bytecode_array.source_position_table = vms.fixed_array_base.length + 3 * pointer_size as u16;
        }
        if vms.bytecode_array.data == 0 {
            // At least back to V8 8.4 (16 = 3*int32 + uint16)
            vms.bytecode_array.data = vms.bytecode_array.source_position_table + pointer_size as u16 + 14;
        }
        if vms.deoptimization_data_index.inlined_function_count == 0 {
            vms.deoptimization_data_index.inlined_function_count = 1;
        }
        if vms.deoptimization_data_index.literal_array == 0 {
            let val = vms.deoptimization_data_index.inlined_function_count + 1;
            vms.deoptimization_data_index.literal_array = val;
        }
        if vms.deoptimization_data_index.shared_function_info == 0 {
            vms.deoptimization_data_index.shared_function_info = 6;
        }
        if vms.deoptimization_data_index.inlining_positions == 0 {
            let val = vms.deoptimization_data_index.shared_function_info + 1;
            vms.deoptimization_data_index.inlining_positions = val;
        }
        if vms.code_kind.baseline == 0 {
            if ver >= v8_ver(9, 0, 240) {
                // Back to V8 9.0.240, and metadata available after that
                vms.code_kind.field_mask = 0xf;
                vms.code_kind.field_shift = 0;
                vms.code_kind.baseline = 11;
            } else {
                // Leave mask and shift to zero, and set baseline to something
                // so that the Baseline code is never triggered.
                vms.code_kind.baseline = 0xff;
            }
        }
        if vms.baseline_data.data == 0 && vms.code_kind.field_mask != 0 {
            // Unfortunately no metadata currently. Has been static.
            vms.baseline_data.data = vms.heap_object.map + 2 * pointer_size as u16;
        }

        Ok(Self { pid, process, version })
    }
}

fn v8_ver(major: u32, minor: u32, build: u32) -> u32 {
    (major << 24) + (minor << 16) + build
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
    read_memory(process_info, process, "v8dbg_type_BaselineData__BASELINE_DATA_TYPE", &mut data.typ.baseline_data);
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
    if !read_memory(process_info, process, "v8dbg_class_JSFunction__code__Code", &mut data.jsfunction.code) {
        read_memory(process_info, process, "v8dbg_class_JSFunction__code__Tagged_Code_", &mut data.jsfunction.code);
    }
    read_memory(process_info, process, "v8dbg_class_JSFunction__shared__SharedFunctionInfo", &mut data.jsfunction.shared_function_info);
    if !read_memory(process_info, process, "v8dbg_class_Code__deoptimization_data__FixedArray", &mut data.code.deoptimization_data) {
        read_memory(process_info, process, "v8dbg_class_Code__deoptimization_data__Tagged_FixedArray_", &mut data.code.deoptimization_data);
    }
    if !read_memory(process_info, process, "v8dbg_class_Code__source_position_table__ByteArray", &mut data.code.source_position_table) {
        read_memory(process_info, process, "v8dbg_class_Code__source_position_table__Tagged_ByteArray_", &mut data.code.source_position_table);
    }
    if !read_memory(process_info, process, "v8dbg_class_Code__instruction_start__uintptr_t", &mut data.code.instruction_start) {
        read_memory(process_info, process, "v8dbg_class_Code__instruction_start__Address", &mut data.code.instruction_start);
    }
    read_memory(process_info, process, "v8dbg_class_Code__instruction_size__int", &mut data.code.instruction_size);
    read_memory(process_info, process, "v8dbg_class_Code__flags__uint32_t", &mut data.code.flags);
    if !read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__name_or_scope_info__Object", &mut data.shared_function_info.name_or_scope_info) {
        read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__name_or_scope_info__Tagged_Object_", &mut data.shared_function_info.name_or_scope_info);
    }
    if !read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__function_data__Object", &mut data.shared_function_info.function_data) {
        read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__function_data__Tagged_Object_", &mut data.shared_function_info.function_data);
    }
    if !read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__script_or_debug_info__Object", &mut data.shared_function_info.script_or_debug_info) {
        if !read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__script_or_debug_info__HeapObject", &mut data.shared_function_info.script_or_debug_info) {
            read_memory(process_info, process, "v8dbg_class_SharedFunctionInfo__script_or_debug_info__Tagged_HeapObject_", &mut data.shared_function_info.script_or_debug_info);
        }
    }
    read_memory(process_info, process, "v8dbg_class_BaselineData__data__Object", &mut data.baseline_data.data);
    if !read_memory(process_info, process, "v8dbg_class_BytecodeArray__source_position_table__Object", &mut data.bytecode_array.source_position_table) {
        read_memory(process_info, process, "v8dbg_class_BytecodeArray__source_position_table__Tagged_HeapObject_", &mut data.bytecode_array.source_position_table);
    }
    read_memory(process_info, process, "v8dbg_class_BytecodeArray__data__uintptr_t", &mut data.bytecode_array.data);
    if process_info.get_symbol("v8dbg_parent_ScopeInfo__HeapObject").is_some() {
        data.scope_info.heap_object = true;
    }
    if process_info.get_symbol("v8dbg_parent_DeoptimizationLiteralArray__WeakFixedArray").is_some() {
        data.deoptimization_literal_array.weak_fixed_array = true;
    }
    read_memory(process_info, process, "v8dbg_class_Script__name__Object", &mut data.script.name);
    read_memory(process_info, process, "v8dbg_class_Script__line_ends__Object", &mut data.script.line_ends);
    read_memory(process_info, process, "v8dbg_class_Script__source__Object", &mut data.script.source);
    return data;
}

fn read_memory<T>(process_info: &ProcessInfo, process: &Process, symbol: &str, data: &mut T) -> bool {
    let addr = process_info.get_symbol(symbol);
    if addr.is_none() {
        if symbol.starts_with("v8dbg_frametype_") {
            unsafe {
                if let Some(data_ptr) = (data as *mut T).cast::<u8>().as_mut() {
                    *data_ptr = 0b11111111u8;
                    return true;
                }
            }
        }
        println!("Failed to get symbol {}", symbol);
        return false;
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
        return true;
    }
    return false;
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