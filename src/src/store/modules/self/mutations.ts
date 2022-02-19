import { SET_LOGGED_IN } from './actions';
import { SelfState } from './state';
import { MutationTree } from 'vuex';
import { AppLoginInterface } from '@/models/login';

const mutations: MutationTree<SelfState> = {
  [SET_LOGGED_IN](state: SelfState, payload: AppLoginInterface): void {
    state.isLoggedIn = payload.isLoggedIn;
    state.appLogoutFunction = payload.logoutFunction;
  }
};

export default mutations;
