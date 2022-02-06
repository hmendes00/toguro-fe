<template>
  <div class="gsn-drawer-menu" :class="{ active: drawerState === DrawerStateType.OPENED }">
    <div class="header">a</div>
    <div class="profile">
      b
      <p class="email">{{ email }}</p>
    </div>
    <div class="other-menus">
      <router-link to="/settings" c></router-link>
    </div>
  </div>
</template>

<style lang="scss" src="./drawer-menu.scss" scoped></style>
<script type="typescript" src="./drawer-menu.ts"></script>
