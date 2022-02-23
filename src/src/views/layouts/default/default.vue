<template>
  <div class="tfe-default-layout">
    <div class="header">
      <div class="left-area">
        <img class="logo" src="@assets/logo.png" />
        <h3 class="logo-name">Cached-In</h3>
        <div class="main-search-area" v-click-outside="() => (hideSearch = true)">
          <n-input
            v-model:value="mainSearchInput"
            @update-value="onMainSearch"
            @focus="() => (hideSearch = !searchUsersResult.length)"
            :loading="isSearching"
            placeholder="Try: Javascript"
          >
            <template #prefix>
              <n-icon :component="Search" />
            </template>
          </n-input>
          <n-card class="search-results" :class="{ active: displaySearchResults }" title="Results">
            <template #header-extra> Found ({{ searchUsersResult.length }}) </template>
            <h3>Users</h3>
            <div class="users-result">
              <div class="user-avatar-wrapper" v-for="userFound of searchUsersResult" :key="userFound.user_id">
                <n-avatar
                  :text-fallback="userFound.display_name"
                  round
                  color="white"
                  :size="52"
                  :src="GetMxImage(userFound.avatar_url)"
                ></n-avatar>

                <span class="displayname">{{ userFound.display_name }}</span>
              </div>
            </div>
            <template #footer>
              <h3>Challenges</h3>
            </template>
          </n-card>
        </div>
      </div>
      <div class="right-area">
        <template v-if="isLoggedIn">
          <template v-if="isLoggedIn">
            <router-link
              v-for="menuApp of mainMenuCustomApps"
              :key="menuApp.appId"
              :to="`/custom-page-app/${menuApp.appId}`"
              >{{ menuApp.label }}</router-link
            >
          </template>
          <n-badge value="10" :max="15" title="New Messages" color="#f66747">
            <n-icon :component="Mail" size="24" color="white" />
          </n-badge>
          <div
            class="avatar-area"
            :class="{ active: isAvatarMenuActive }"
            @click="() => (isAvatarMenuActive = !isAvatarMenuActive)"
            v-click-outside="() => (isAvatarMenuActive = false)"
          >
            <n-avatar round :text-fallback="userName" :src="myAvatarUrl" size="large"></n-avatar>
            <ul class="avatar-sub-menu">
              <li class="info-li">
                <div class="basic-info">
                  <n-avatar :text-fallback="userName" round :src="myAvatarUrl" :size="52"></n-avatar>
                  <div class="display-name-username">
                    <h3>{{ displayName }}</h3>
                    <span>@{{ userName }}</span>
                  </div>
                </div>
                <div class="badges">
                  <n-badge :value="10" :max="15" title="Assessments taken" type="success">
                    <n-icon :component="CheckmarkDoneCircle" color="#777777" size="24" />
                  </n-badge>
                  <n-badge :value="16" :max="15" title="Profile Views" type="success">
                    <n-icon :component="Eye" size="24" color="#777777" />
                  </n-badge>
                  <n-badge :value="4" :max="15" title="Likes Received" type="success">
                    <n-icon :component="ThumbsUp" color="#777777" size="24" />
                  </n-badge>
                </div>
                <n-button class="view-edit-button" @click="goToProfile('')">View/Edit Profile</n-button>
              </li>
              <li class="line-separator"></li>
              <li><a href="#">See Activity</a></li>
              <li class="line-separator"></li>
              <li><a href="#" @click="logout">Logout</a></li>
            </ul>
          </div>
        </template>
        <router-link v-if="!isLoggedIn" to="/login">Login</router-link>
      </div>
    </div>
    <div class="content">
      <div class="main-content-overlay" :class="{ active: shouldDisplayContentOverlay }"></div>
      <router-view></router-view>
    </div>
    <div class="footer"></div>
  </div>
</template>

<style lang="scss" src="./default.scss" scoped></style>
<script setup lang="ts">
  import { LOAD_CUSTOM_APPS } from '@/store/modules/app/actions';
  import { SET_LOGOUT } from '@/store/modules/self/actions';
  import { computed, onMounted, provide, ref, watch } from 'vue';
  import { appStore, selfStore } from '@/store';
  import CustomAppService from '@/services/custom-app-service';
  import { GetDisplayName, GetUsername, GetMyAvatarUrl, SearchUsers, GetMxImage } from '@/helpers/matrix';
  import { NButton, NBadge, NInput, NIcon, NCard } from 'naive-ui';
  import NAvatar from '@components/avatar/avatar.vue';
  import { Mail, Search, CheckmarkDoneCircle, Eye, ThumbsUp } from '@vicons/ionicons5';
  import vClickOutside from '@directives/click-outside';
  import { UserSearched } from '@models/matrix';
  import { useDebounceFn } from '@vueuse/core';
  import router from '@/router';

  const isLoggedIn = computed<boolean>(() => selfStore.getters['isLoggedIn']);
  const isAvatarMenuActive = ref(false),
    isSearching = ref(false),
    hideSearch = ref(false),
    shouldDisplayContentOverlay = ref(false);
  const mainSearchInput = ref('');

  const displayName = ref(GetDisplayName()),
    userName = ref(GetUsername()),
    myAvatarUrl = ref(GetMyAvatarUrl());

  provide('addToSearch', (term: string) => {
    mainSearchInput.value = term;
    onMainSearch(mainSearchInput.value);
  });

  const searchUsersResult = ref<Array<UserSearched>>([]);

  const goToProfile = (userId: string) => {
    return router.push({ name: 'profile', params: { userId } });
  };

  const displaySearchResults = computed(() => {
    const shouldDisplay = !hideSearch.value && searchUsersResult.value.length > 0;
    shouldDisplayContentOverlay.value = shouldDisplay;
    return shouldDisplay;
  });

  const onMainSearch = useDebounceFn(async (input: string) => {
    isSearching.value = true;
    const result = await SearchUsers(input);
    searchUsersResult.value = result?.results || [];
    hideSearch.value = !searchUsersResult.value.length;
    isSearching.value = false;
  }, 500);

  /**
   * Loading menu (header) apps
   */
  const mainMenuCustomApps = computed(() =>
    Object.values(appStore.state.customApps)
      .filter((app) => app.target === 'menu')
      .map(({ label, appId }) => ({ label, appId }))
  );

  const logout = () => {
    selfStore.dispatch(SET_LOGOUT);
  };
</script>
