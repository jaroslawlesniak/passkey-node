import { authentication } from '../../controllers';
import { withRouter } from '../routing';

export default withRouter(router => {
  router.get('/', authentication.index);
});
