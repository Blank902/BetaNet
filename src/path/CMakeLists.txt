# Link libsodium for naming/trust/alias ledger
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})
link_libraries(${SODIUM_LIBRARIES})
# Placeholder for path module