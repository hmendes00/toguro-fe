import { AppState, CustomApp, DrawerState } from './state';
import { GetterTree } from 'vuex';

const getters: GetterTree<AppState, {}> = {
  drawerState(state: AppState): DrawerState {
    return state.drawerState;
  },
  menuCustomApps(state: AppState): CustomApp[] {
    const menuApps = Object.values(state.customApps).filter((app) => app.target === 'menu');
    return menuApps;
  },
  mainMenuCustomApps(state: AppState): { label: string; appId: string }[] {
    const menuApps = Object.values(state.customApps)
      .filter((app) => app.target === 'menu')
      .map((app) => ({ label: app.label, appId: app.appId }));
    return menuApps;
  }
};

export default getters;
