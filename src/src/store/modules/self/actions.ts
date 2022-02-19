import { SelfState } from './state';
import { ActionTree, ActionContext } from 'vuex';
import { AppLoginInterface } from '@/models/login';

export const SET_LOGGED_IN = 'SELF - SET_LOGGED_IN';
export const SET_LOGOUT = 'SELF - LOGOUT';

const actions: ActionTree<SelfState, {}> = {
  [SET_LOGGED_IN]({ commit }: ActionContext<SelfState, {}>, payload: AppLoginInterface): void {
    commit(SET_LOGGED_IN, payload);
  },
  [SET_LOGOUT]({ commit, getters }: ActionContext<SelfState, {}>): void {
    getters.appLogoutFunction();
    commit(SET_LOGGED_IN, { isLoggedIn: false });
  }
};
export default actions;
