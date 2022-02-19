import { CACHE_CUSTOM_APPS } from './actions';
import { AppState, CustomApp } from './state';
import { MutationTree } from 'vuex';

const mutations: MutationTree<AppState> = {
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
