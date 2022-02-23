import { SelfState } from './state';
import { ActionTree, ActionContext } from 'vuex';
import { AppLoginInterface } from '@/models/login';
import { SetClient } from '@/helpers/matrix';

export const SET_LOGGED_IN = 'SELF - SET_LOGGED_IN';
export const SET_LOGOUT = 'SELF - LOGOUT';
// export const SET_USER_BASIC_INFO = 'SELF - SET_USER_BASIC_INFO';

const actions: ActionTree<SelfState, {}> = {
  async [SET_LOGGED_IN]({ commit }: ActionContext<SelfState, {}>, payload: AppLoginInterface): Promise<void> {
    await SetClient(payload.accessToken);
    commit(SET_LOGGED_IN, payload);
  },
  async [SET_LOGOUT]({ commit, getters, dispatch }: ActionContext<SelfState, {}>): Promise<void> {
    await getters.appLogoutFunction();
    commit(SET_LOGGED_IN, { isLoggedIn: false });
    location.href = '/login';
  }
  // [SET_USER_BASIC_INFO]({ commit }: ActionContext<SelfState, {}>, userBasicInfo: User): void {
  //   commit(SET_USER_BASIC_INFO, { isLoggedIn: false });
  // }
};
export default actions;
