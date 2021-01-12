#include <cstdio>
#include <thread>

unsigned int hardware_thread_count() {
    // clamp to minimum of 1
    return std::max<unsigned int>(std::thread::hardware_concurrency(), 1);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    std::printf("Detected %u hardware threads \n", hardware_thread_count());
    return 0;
}
