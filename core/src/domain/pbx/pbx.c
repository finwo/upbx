#include "domain/pbx/pbx.h"

#include "domain/pbx/call.h"
#include "domain/pbx/extension.h"
#include "domain/pbx/media_proxy.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/transport_udp.h"
#include "rxi/log.h"

void pbx_init(void) {
  log_info("pbx: initializing");

  pbx_extension_init();
  pbx_registration_init();
  pbx_call_init();
  pbx_media_proxy_init();

  log_info("pbx: initialized");
}

void pbx_shutdown(void) {
  log_info("pbx: shutting down");

  pbx_media_proxy_shutdown();
  pbx_call_shutdown();
  pbx_registration_shutdown();
  pbx_extension_shutdown();

  log_info("pbx: shutdown complete");
}
