import { SelfState } from './state';
import { ActionTree, ActionContext } from 'vuex';

export const SET_LOGGED_IN = 'SELF - SET_LOGGED_IN';

const actions: ActionTree<SelfState, {}> = {
  [SET_LOGGED_IN]({ commit }: ActionContext<SelfState, {}>, isLoggedIn: boolean): void {
    commit(SET_LOGGED_IN, isLoggedIn);
  }
};
export default actions;
