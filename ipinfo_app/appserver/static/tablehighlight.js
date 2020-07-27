require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc, TableView) {
	var major, minor, critical,value;
	var color,flag;
	var classname;
     // Row Coloring Example with custom, client-side range interpretation
    var CustomRangeRenderer = TableView.BaseCellRenderer.extend({
		
        canRender: function(cell) {
            // Enable this custom cell renderer for both the active_hist_searches and the active_realtime_searches field
		
            return _(['AbbrName','color']).contains(cell.field);
        },
		
        render: function($td, cell) {
            // Add a class to the cell based on the returned value

		if (cell.field === 'color'){	
				
				color = cell.value;
				
		}
		
		if (cell.field === 'AbbrName'){	
				
				
				
				if(color === "1"){
					
					$td.addClass('range-cell').addClass('range-none');
				}
				else if(color === "2"){
					
					$td.addClass('range-cell').addClass('range-low');
				}
				else if(color === "3"){
					
					$td.addClass('range-cell').addClass('range-elevated');
				}else {
					
					$td.addClass('range-cell').addClass('range-severe');
				}
		}
				
			
			
		
		$td.text(cell.value);
		
		
        }
	
	
    });
	
	console.log( mvc.Components.get('#table'));
	
    mvc.Components.get('highlight1').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}}
    });
	
	mvc.Components.get('highlight2').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight3').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight4').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight5').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight6').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight7').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight8').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight9').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight10').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight11').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight12').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight13').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight14').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    }); mvc.Components.get('highlight15').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight16').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    }); mvc.Components.get('highlight17').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight18').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight19').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight20').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight21').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight22').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight23').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight24').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	mvc.Components.get('highlight25').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight26').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight27').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight28').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight29').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight30').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight31').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight32').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight33').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight34').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight35').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight36').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight37').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight38').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    }); mvc.Components.get('highlight39').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight40').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    }); mvc.Components.get('highlight41').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight42').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	 mvc.Components.get('highlight43').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.
		 
       if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	mvc.Components.get('highlight44').getVisualization(function(tableView) {
        // Add custom cell renderer, the table will re-render automatically.

         if(tableView != null){ tableView.addCellRenderer(new CustomRangeRenderer()); 
		
         tableView.render();}
    });
	
	});

