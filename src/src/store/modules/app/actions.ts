import CustomAppService from '@/services/custom-app-service';
import { ActionContext, ActionTree } from 'vuex';
import { AppState, DrawerState } from './state';

export const SET_DRAWER_STATE = 'APP - SET_DRAWER_STATE';
export const LOAD_CUSTOM_APPS = 'APP - LOAD_CUSTOM_APPS';
export const CACHE_CUSTOM_APPS = 'APP - CACHE_CUSTOM_APPS';

const actions: ActionTree<AppState, {}> = {
  [SET_DRAWER_STATE]({ commit }: ActionContext<AppState, {}>, drawerState: DrawerState): void {
    commit(SET_DRAWER_STATE, drawerState);
  },
  [LOAD_CUSTOM_APPS]({ commit }: ActionContext<AppState, {}>, directory: string): void {
    const apps = CustomAppService.getAllFor(directory);
    commit(CACHE_CUSTOM_APPS, apps);
  }
};
export default actions;
