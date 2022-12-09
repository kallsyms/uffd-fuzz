// To bench djpeg with 01_fork and 02_vfork (like in the blog post), use:
/* #define TARGET "./libjpeg-turbo/build/djpeg-static" */
/* #define TARGET_ARGS ((char * const []){"djpeg-static", "/tmp/tux.jpg", NULL}) */
/* #define ITERS 10000 */

#define TARGET "./target"
#define TARGET_ARGS ((char * const []){"./target", NULL})
#define ITERS 10000
