<template>
  <div class="tfe-default-layout">
    <div class="header">
      <div class="left-area">
        <img class="logo" src="@assets/logo.png" />
      </div>
      <div class="right-area">
        <template v-if="isLoggedIn">
          <router-link
            v-for="menuApp of mainMenuCustomApps"
            :key="menuApp.appId"
            :to="`/custom-page-app/${menuApp.appId}`"
            >{{ menuApp.label }}</router-link
          >
          <a href="#" @click="logout">Logout</a>
        </template>
        <router-link v-if="!isLoggedIn" to="/login">Login</router-link>
      </div>
    </div>
    <div class="content">
      <router-view></router-view>
    </div>
    <div class="footer"></div>
  </div>
</template>

<style lang="scss" src="./default.scss" scoped></style>
<script setup lang="ts">
  import { LOAD_CUSTOM_APPS } from '@/store/modules/app/actions';
  import { SET_LOGOUT } from '@/store/modules/self/actions';
  import { computed, onMounted, watch } from 'vue';
  import { appStore, selfStore } from '@/store';
  import CustomAppService from '@/services/custom-app-service';

  const isLoggedIn = computed<boolean>(() => selfStore.getters['isLoggedIn']);

  /**
   * Loading menu (header) apps
   */
  const mainMenuCustomApps = computed(() =>
    Object.values(appStore.state.customApps)
      .filter((app) => app.target === 'menu')
      .map(({ label, appId }) => ({ label, appId }))
  );

  /**
   * Register/Load required-globally apps. e.g. apps that dispatches global-events
   * Login-apps are an example of it knowing they will dispatch the event for login-updated
   * This won't necessarily instantiate the app, but register it.
   */
  watch(appStore.state.customApps, (apps) => {
    Object.values(appStore.state.customApps)
      .filter((app) => {
        return app.requiredGlobally;
      })
      .forEach((app) => {
        CustomAppService.addScriptToHead(app);
      });
  });

  const logout = () => {
    selfStore.dispatch(SET_LOGOUT);
  };

  onMounted(() => {
    appStore.dispatch(LOAD_CUSTOM_APPS);
  });
</script>
