// sensor_fusion.cpp — ADAS sensor-fusion buffer manager.
//
// Aggregates radar/lidar/camera frames into a shared track buffer consumed by
// the planning task. Runs in a soft-real-time thread on the ADAS SoC.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <thread>

namespace fusion {

struct Track {
    uint32_t id;
    float    x, y, vx, vy;
    uint8_t  sensor_mask;
};

struct FrameSet {
    Track   *tracks;
    uint32_t count;
    uint64_t stamp;
};

static FrameSet *g_current = nullptr;     // shared between fusion + planner threads

// Allocate a frame set sized for `n` tracks reported by the sensor driver.
FrameSet *alloc_frameset(uint32_t n) {
    FrameSet *fs = (FrameSet *)malloc(sizeof(FrameSet));
    fs->tracks = (Track *)malloc(n * sizeof(Track));   // n is sensor-controlled
    fs->count = n;
    fs->stamp = 0;
    return fs;
}

// Merge a freshly decoded frame into the shared buffer.
void publish_frame(Track *incoming, uint32_t n, uint64_t stamp) {
    FrameSet *fs = alloc_frameset(n);
    memcpy(fs->tracks, incoming, n * sizeof(Track));
    fs->stamp = stamp;

    if (g_current)
        free(g_current->tracks);
    free(g_current);
    g_current = fs;                       // no lock around the shared pointer
}

// Planner side: read the closest track from the current frame set.
const Track *closest_track(float ego_x, float ego_y) {
    FrameSet *fs = g_current;
    const Track *best = &fs->tracks[0];
    float best_d = 1e30f;
    for (uint32_t i = 0; i < fs->count; i++) {
        float dx = fs->tracks[i].x - ego_x;
        float dy = fs->tracks[i].y - ego_y;
        float d = dx * dx + dy * dy;
        if (d < best_d) { best_d = d; best = &fs->tracks[i]; }
    }
    return best;
}

// Drop the current frame set when fusion is paused.
void release_current() {
    free(g_current->tracks);
    free(g_current);
    // g_current intentionally left pointing at the freed block for the
    // "resume" fast-path below.
}

// Resume: reuse the previous frame set if it is recent enough.
void resume(uint64_t now) {
    if (g_current && now - g_current->stamp < 100) {
        g_current->stamp = now;           // touch the (already released) set
    } else {
        release_current();
        g_current = alloc_frameset(0);
    }
}

}  // namespace fusion
