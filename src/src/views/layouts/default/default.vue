<template>
  <div class="gsn-default-layout">
    <div class="header">
      <div class="left-area">
        <img class="logo" src="@assets/logo.png" />
      </div>
      <div class="right-area">
        <router-link v-if="!isLoggedIn" to="/login"> sign in </router-link>
      </div>
    </div>
    <div class="content">
      <router-view></router-view>
    </div>
    <div class="footer">
      <router-link
        v-for="menuApp of mainMenuCustomApps"
        :key="menuApp.appId"
        :to="`/custom-page-app/${menuApp.appId}`"
        >{{ menuApp.label }}</router-link
      >
    </div>
    <!-- <gsn-drawer-menu /> -->
  </div>
</template>

<style lang="scss" src="./default.scss" scoped></style>
<script setup lang="ts">
  // import GsnDrawerMenu from '@containers/drawer-menu/drawer-menu.vue';
  import { LOAD_CUSTOM_APPS } from '@/store/modules/app/actions';
  import { computed, onMounted } from 'vue';
  import { appStore, selfStore } from '@/store';

  const isLoggedIn = computed(() => selfStore.getters['self/isLoggedIn']);
  const mainMenuCustomApps = computed(() =>
    Object.values(appStore.state.customApps)
      .filter((app) => app.target === 'menu')
      .map(({ label, appId }) => ({ label, appId }))
  );

  onMounted(() => {
    appStore.dispatch(LOAD_CUSTOM_APPS);
  });
</script>
