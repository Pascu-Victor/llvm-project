set(LLVM_LINK_COMPONENTS
  Support
  TargetParser
  )

add_lld_tool(lld
  lld.cpp

  SUPPORT_PLUGINS
  GENERATE_DRIVER
  )
export_executable_symbols_for_plugins(lld)

set(LLD_DRIVER_LIBS lldCommon)
set(LLD_DRIVER_DEFINES)

if(LLD_ENABLE_COFF)
  list(APPEND LLD_DRIVER_LIBS lldCOFF)
  list(APPEND LLD_DRIVER_DEFINES LLD_ENABLE_COFF=1)
endif()
if(LLD_ENABLE_ELF)
  list(APPEND LLD_DRIVER_LIBS lldELF)
  list(APPEND LLD_DRIVER_DEFINES LLD_ENABLE_ELF=1)
endif()
if(LLD_ENABLE_MACHO)
  list(APPEND LLD_DRIVER_LIBS lldMachO)
  list(APPEND LLD_DRIVER_DEFINES LLD_ENABLE_MACHO=1)
endif()
if(LLD_ENABLE_MINGW)
  list(APPEND LLD_DRIVER_LIBS lldMinGW)
  list(APPEND LLD_DRIVER_DEFINES LLD_ENABLE_MINGW=1)
endif()
if(LLD_ENABLE_WASM)
  list(APPEND LLD_DRIVER_LIBS lldWasm)
  list(APPEND LLD_DRIVER_DEFINES LLD_ENABLE_WASM=1)
endif()

target_compile_definitions(lld PRIVATE ${LLD_DRIVER_DEFINES})

function(lld_target_link_libraries target type)
  if (TARGET obj.${target})
    target_link_libraries(obj.${target} ${ARGN})
  endif()

  get_property(LLVM_DRIVER_TOOLS GLOBAL PROPERTY LLVM_DRIVER_TOOLS)
  if(LLVM_TOOL_LLVM_DRIVER_BUILD AND ${target} IN_LIST LLVM_DRIVER_TOOLS)
    set(target llvm-driver)
  endif()

  target_link_libraries(${target} ${type} ${ARGN})
endfunction()

lld_target_link_libraries(lld
  PRIVATE
  ${LLD_DRIVER_LIBS}
  )

if(NOT LLD_SYMLINKS_TO_CREATE)
  if(LLD_ENABLE_COFF)
    list(APPEND LLD_SYMLINKS_TO_CREATE lld-link)
  endif()
  if(LLD_ENABLE_ELF)
    list(APPEND LLD_SYMLINKS_TO_CREATE ld.lld)
  endif()
  if(LLD_ENABLE_MACHO)
    list(APPEND LLD_SYMLINKS_TO_CREATE ld64.lld)
  endif()
  if(LLD_ENABLE_WASM)
    list(APPEND LLD_SYMLINKS_TO_CREATE wasm-ld)
  endif()
endif()

foreach(link ${LLD_SYMLINKS_TO_CREATE})
  add_lld_symlink(${link} lld)
endforeach()

if(LLVM_TOOL_LLVM_DRIVER_BUILD)
  set_property(GLOBAL APPEND PROPERTY LLVM_DRIVER_HIDDEN_TOOL_ALIASES_lld ld)
endif()
