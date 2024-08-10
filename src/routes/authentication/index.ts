import { authentication } from "@/controllers";

import { withRouter } from "../routing";
import { Routes } from "../types";

const routes: Routes = () =>
  withRouter((router) => {
    router.get("/", authentication.index);
    router.post(
      "/passkey/register/begin",
      authentication.passkeyRegistrationStart,
    );
    router.post(
      "/passkey/register/finish",
      authentication.passkeyRegistrationFinish,
    );
    router.post("/passkey/login/begin", authentication.passkeyLoginStart);
    router.post("/passkey/login/finish", authentication.passkeyLoginFinish);
  });

export default routes;
