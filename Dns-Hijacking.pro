TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        ip.cpp \
        main.cpp \
        packet_handle.cpp \
        target_info.cpp

HEADERS += \
    header.h \
    ip.h \
    packet_handle.h \
    target_info.h
