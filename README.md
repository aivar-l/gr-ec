#gr-ec
This GNU Radio module is originally created by Martin Neerot from ESTCube-1 student satellite team.
It can be used to decode G3RUH scrambled AX.25 packets.

#linux install
    mkdir build
    cd build/
    cmake ..
    make
    make install

#mac os x install
follow gnuradio installation instructions here https://github.com/andresv/homebrew-gnuradio

gnuradio uses homebrew pyhton however cmake is unable to find correct python version therefore it is given here as argument

    mkdir build
    cd build/
    cmake -DPYTHON_LIBRARY=/usr/local/Frameworks/Python.framework/Versions/2.7/Python ..
    make
    make install
