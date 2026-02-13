#pragma once

#ifndef HVISOR_VIRTIO_API_H
#define HVISOR_VIRTIO_API_H

#ifdef __cplusplus
extern "C" {
#endif

// virtio subsystem entry point
int virtio_start(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif // HVISOR_VIRTIO_API_H
