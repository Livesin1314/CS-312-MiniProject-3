const bcrypt = require("bcrypt");
async function main(){
   //generate a hash for each password
   const passwords = [
      "AliceBLog123!",
      "BobBlog123!",
      "CharlieBlog123!"
   ];
   for (const password of passwords){
      const hash = await bcrypt.hash(password, 10);
      console.log(password + " => " + hash);
   }
}

main();