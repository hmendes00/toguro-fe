import CustomAppService from '@/services/custom-app-service';
import { ActionContext, ActionTree } from 'vuex';
import { AppState } from './state';

export const LOAD_CUSTOM_APPS = 'APP - LOAD_CUSTOM_APPS';
export const CACHE_CUSTOM_APPS = 'APP - CACHE_CUSTOM_APPS';

const actions: ActionTree<AppState, {}> = {
  [LOAD_CUSTOM_APPS]({ commit }: ActionContext<AppState, {}>, directory: string): void {
    const apps = CustomAppService.getAllFor(directory);
    commit(CACHE_CUSTOM_APPS, apps);
  }
};
export default actions;
