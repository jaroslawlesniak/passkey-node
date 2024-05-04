import { authentication } from '@/controllers';
import { withRouter } from '../routing';
import { Routes } from '../types';

const routes: Routes = () => withRouter(router => {
  router.get('/', authentication.index);
  router.get('/passkey/register/begin', authentication.passkeyRegistrationStart);
  router.get('/passkey/register/finish', authentication.passkeyRegistrationFinish);
  router.get('/passkey/login/begin', authentication.passkeyLoginStart);
  router.get('/passkey/login/finish', authentication.passkeyLoginFinish);
});

export default routes;
