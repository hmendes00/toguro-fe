import { SelfState } from './state';
import { GetterTree } from 'vuex';

const getters: GetterTree<SelfState, {}> = {
  isLoggedIn(state: SelfState): boolean {
    return state.isLoggedIn;
  },
  appLogoutFunction(state: SelfState): Function {
    return state.appLogoutFunction!;
  }
};

export default getters;
