import { authentication } from '@/controllers';
import { withRouter } from '../routing';
import { Routes } from '../types';

const routes: Routes = () => withRouter(router => {
  router.get('/', authentication.index);
});

export default routes;
