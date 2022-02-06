import state from './state';
import mutations from './mutations';
import actions from './actions';
import getters from './getters';

const store = {
  state,
  getters,
  mutations,
  actions,
  namespaced: true
};

export default store;
