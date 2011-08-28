module.exports.completeLogin = function(auth) {
  return function(req,res) {
    var token = req.param("token");
    auth.retrieve_details(token, function(r){ 
      if(r && r.token == token) {
        req.session.user = r.user;
        req.session.save(function(){
          res.redirect('/');
        });      
      } else {
        res.redirect('/');
      }
    });
  };
};