// in vue 3 you need v prefix for directives
const vClickOutside = {
  beforeMount(el: any, binding: any) {
    // Provided expression must evaluate to a function.
    if (typeof binding.value !== 'function') {
      const compName = binding.instance.name;
      let warn = `[v-click-outside:] provided expression '${binding.expression}' is not a function, but has to be`;
      if (compName) {
        warn += `Found in component '${compName}'`;
      }

      console.warn(warn);
      return;
    }

    // Bind handler
    el._vueClickOutside_ = (e: Event) => {
      if (!el.contains(e.target) && el !== e.target) {
        binding.value(e);
      }
    };

    // Add Event Listeners
    document.addEventListener('mouseup', el._vueClickOutside_);
  },

  beforeUnmount: function (el: any) {
    // Remove Event Listeners
    document.removeEventListener('mouseup', el._vueClickOutside_);
    el._vueClickOutside_ = null;
  }
};

export default vClickOutside;
