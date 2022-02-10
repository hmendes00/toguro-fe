import { CACHE_CUSTOM_APPS, SET_DRAWER_STATE } from './actions';
import { DrawerState, AppState, CustomApp } from './state';
import { MutationTree } from 'vuex';

const mutations: MutationTree<AppState> = {
  [SET_DRAWER_STATE](state: AppState, drawerState: DrawerState): void {
    state.drawerState = drawerState;
  },
  [CACHE_CUSTOM_APPS](state: AppState, customApps: CustomApp[]): void {
    const newCustomApps = customApps.filter((app) => {
      return !state.customApps[app.appId];
    });

    newCustomApps.forEach((app) => {
      state.customApps[app.appId] = app;
    });
  }
};

export default mutations;
