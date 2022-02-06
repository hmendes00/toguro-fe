import { SET_LOGGED_IN } from './actions';
import { SelfState } from './state';
import { MutationTree } from 'vuex';

const mutations: MutationTree<SelfState> = {
  [SET_LOGGED_IN](state: SelfState, isLoggedIn: boolean): void {
    state.isLoggedIn = isLoggedIn;
  }
};

export default mutations;
