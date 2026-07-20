#include <lwip/arch.h>
#include <uv.h>

u32_t sys_now(void)
{
    return (u32_t)(uv_hrtime() / 1000000u);
}
