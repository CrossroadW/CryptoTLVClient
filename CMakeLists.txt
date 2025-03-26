cmake_minimum_required(VERSION 3.30)
project(designpattern LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(QT NAMES Qt6  REQUIRED )
find_package(Qt6 REQUIRED COMPONENTS Widgets Network Gui Core5Compat)
add_executable(designpattern "")
target_link_libraries(designpattern PRIVATE Qt6::Widgets Qt6::Network Qt6::Gui Qt6::Core5Compat)
set_target_properties(designpattern
PROPERTIES AUTOMOC ON
           )
target_sources(designpattern PRIVATE
        main.cpp
        tcpmgr.h tcpmgr.cpp
        tlv_parse.h tlv_parse.cpp
        login_window.h login_window.cpp
        encrypto_parse.h encrypto_parse.cpp
        encrypto_utils.h encrypto_utils.cpp)

find_package(Botan CONFIG REQUIRED)
target_link_libraries(designpattern PRIVATE Botan::Botan ssl crypto)