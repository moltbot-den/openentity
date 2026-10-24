// openentityidentitystandard.com (and www) is a permanent alias of openentity.org.
// oeis.dev points at the repo until the developer hub ships in Phase 3.
export default {
  fetch(request) {
    const url = new URL(request.url);
    if (url.hostname === "oeis.dev" || url.hostname === "www.oeis.dev") {
      return Response.redirect("https://github.com/moltbot-den/openentity", 302);
    }
    return Response.redirect(`https://openentity.org${url.pathname}${url.search}`, 301);
  },
};
