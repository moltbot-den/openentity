// openentityidentitystandard.com (and www) is a permanent alias of openentity.org.
// oeis.dev is the developer hub, served from AWS (infra/lib/stack.ts, HubDist), not by this Worker.
export default {
  fetch(request) {
    const url = new URL(request.url);
    return Response.redirect(`https://openentity.org${url.pathname}${url.search}`, 301);
  },
};
