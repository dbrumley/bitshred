import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Shape;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.util.Iterator;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

import prefuse.Display;
import prefuse.Visualization;
import prefuse.action.ActionList;
import prefuse.action.RepaintAction;
import prefuse.action.animate.ColorAnimator;
import prefuse.action.assignment.ColorAction;
import prefuse.action.layout.Layout;
import prefuse.action.layout.graph.SquarifiedTreeMapLayout;
import prefuse.controls.ControlAdapter;
import prefuse.data.Schema;
import prefuse.data.Tree;
import prefuse.data.expression.Predicate;
import prefuse.data.expression.parser.ExpressionParser;
import prefuse.data.io.TreeMLReader;
import prefuse.data.query.SearchQueryBinding;
import prefuse.render.AbstractShapeRenderer;
import prefuse.render.DefaultRendererFactory;
import prefuse.render.LabelRenderer;
import prefuse.util.ColorLib;
import prefuse.util.ColorMap;
import prefuse.util.FontLib;
import prefuse.util.PrefuseLib;
import prefuse.util.UpdateListener;
import prefuse.util.ui.JFastLabel;
import prefuse.util.ui.JSearchPanel;
import prefuse.util.ui.UILib;
import prefuse.visual.DecoratorItem;
import prefuse.visual.NodeItem;
import prefuse.visual.VisualItem;
import prefuse.visual.VisualTree;
import prefuse.visual.expression.InGroupPredicate;
import prefuse.visual.sort.TreeDepthItemSorter;


public class ClusterMap extends Display {

    public static final String CDB_TREE = "cdb_tree.xml";
    
    // create data description of labels, setting colors, fonts ahead of time
    private static final Schema LABEL_SCHEMA = PrefuseLib.getVisualItemSchema();
    static {
        LABEL_SCHEMA.setDefault(VisualItem.INTERACTIVE, false);
        LABEL_SCHEMA.setDefault(VisualItem.TEXTCOLOR, ColorLib.gray(200));
        LABEL_SCHEMA.setDefault(VisualItem.FONT, FontLib.getFont("Tahoma",16));
    }
    
    private static final String tree = "tree";
    private static final String treeNodes = "tree.nodes";
    private static final String treeEdges = "tree.edges";
    private static final String labels = "labels";

    private SearchQueryBinding searchQ;
    
    public ClusterMap(Tree t) {
        super(new Visualization());
        
        // add the tree to the visualization
        VisualTree vt = m_vis.addTree(tree, t);
        m_vis.setVisible(treeEdges, null, false);
        
        // ensure that only leaf nodes are interactive
        Predicate noLeaf = (Predicate)ExpressionParser.parse("childcount()>0");
        m_vis.setInteractive(treeNodes, noLeaf, false);

        // add labels to the visualization
        // first create a filter to show labels only at top-level nodes
        Predicate labelP = (Predicate)ExpressionParser.parse("treedepth()=-1");
        // now create the labels as decorators of the nodes
        m_vis.addDecorators(labels, treeNodes, labelP, LABEL_SCHEMA);
        
        // set up the renderers - one for nodes and one for labels
        DefaultRendererFactory rf = new DefaultRendererFactory();
        rf.add(new InGroupPredicate(treeNodes), new NodeRenderer());
        rf.add(new InGroupPredicate(labels), new LabelRenderer("name"));
        m_vis.setRendererFactory(rf);
                       
        // border colors
        final ColorAction borderColor = new BorderColorAction(treeNodes);
        final ColorAction fillColor = new FillColorAction(treeNodes);
        
        // color settings
        ActionList colors = new ActionList();
        colors.add(fillColor);
        colors.add(borderColor);
        m_vis.putAction("colors", colors);
        
        // animate paint change
        ActionList animatePaint = new ActionList(400);
        animatePaint.add(new ColorAnimator(treeNodes));
        animatePaint.add(new RepaintAction());
        m_vis.putAction("animatePaint", animatePaint);
        
        // create the single filtering and layout action list
        ActionList layout = new ActionList();
        layout.add(new SquarifiedTreeMapLayout(tree));
        layout.add(new LabelLayout(labels));
        layout.add(colors);
        layout.add(new RepaintAction());
        m_vis.putAction("layout", layout);
        
        // initialize our display
        setSize(1024,768);
        setItemSorter(new TreeDepthItemSorter());
        addControlListener(new ControlAdapter() {
            public void itemEntered(VisualItem item, MouseEvent e) {
                item.setStrokeColor(borderColor.getColor(item));
                item.getVisualization().repaint();
            }
            public void itemExited(VisualItem item, MouseEvent e) {
                item.setStrokeColor(item.getEndStrokeColor());
                item.getVisualization().repaint();
            }           
        });
        
        searchQ = new SearchQueryBinding(vt.getNodeTable(), "name");
        searchQ = new SearchQueryBinding(vt.getNodeTable(), "vlabel", searchQ.getSearchSet());
        m_vis.addFocusGroup(Visualization.SEARCH_ITEMS, searchQ.getSearchSet());
        searchQ.getPredicate().addExpressionListener(new UpdateListener() {
            public void update(Object src) {
                m_vis.cancel("animatePaint");
                m_vis.run("colors");
                m_vis.run("animatePaint");
            }
        });
        
        // perform layout
        m_vis.run("layout");
    }
    
    public SearchQueryBinding getSearchQuery() {
        return searchQ;
    }
    
    public static void main(String argv[]) {
        UILib.setPlatformLookAndFeel();
        JComponent treemap = demo(CDB_TREE);
        
        JFrame frame = new JFrame("BitShred :: Malware Cluster Graph");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setContentPane(treemap);
        frame.pack();
        frame.setVisible(true);
    }
    
    public static JComponent demo() {
        return demo(CDB_TREE);
    }
    
    public static JComponent demo(String datafile) {
        Tree t = null;
        try {
            t = (Tree)new TreeMLReader().readGraph(datafile);
        } catch ( Exception e ) {
            e.printStackTrace();
            System.exit(1);
        }
        
        // create a new treemap
        final ClusterMap treemap = new ClusterMap(t);
        
        // create a search panel for the tree map
        JSearchPanel search = treemap.getSearchQuery().createSearchPanel();
        search.setShowResultCount(true);
        search.setBorder(BorderFactory.createEmptyBorder(5,5,4,0));
        search.setFont(FontLib.getFont("Tahoma", Font.PLAIN, 11));
        
        final JFastLabel title = new JFastLabel("                 ");
        title.setPreferredSize(new Dimension(350, 20));
        title.setVerticalAlignment(SwingConstants.BOTTOM);
        title.setBorder(BorderFactory.createEmptyBorder(3,0,0,0));
        title.setFont(FontLib.getFont("Tahoma", Font.PLAIN, 16));
        
        treemap.addControlListener(new ControlAdapter() {
            public void itemEntered(VisualItem item, MouseEvent e) {
                title.setText(item.getString("name")+" ("+item.getString("vlabel")+")");
            }
            public void itemExited(VisualItem item, MouseEvent e) {
                title.setText(null);
            }
        });
        
        Box box = UILib.getBox(new Component[]{title,search}, true, 10, 3, 0);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(treemap, BorderLayout.CENTER);
        panel.add(box, BorderLayout.SOUTH);
        UILib.setColor(panel, Color.BLACK, Color.GRAY);
        return panel;
    }
    
    public static class BorderColorAction extends ColorAction {
        
        public BorderColorAction(String group) {
            super(group, VisualItem.STROKECOLOR);
        }
        
        public int getColor(VisualItem item) {
            NodeItem nitem = (NodeItem)item;
            if ( nitem.isHover() )
                return ColorLib.rgb(99,130,191);
            
            int depth = nitem.getDepth();
            if ( depth < 2 ) {
                return ColorLib.gray(100);
            } else if ( depth < 4 ) {
                return ColorLib.gray(75);
            } else {
                return ColorLib.gray(50);
            }
        }
    }
    
    public static class FillColorAction extends ColorAction {
        private ColorMap cmap = new ColorMap(
            ColorLib.getInterpolatedPalette(10,
                ColorLib.rgb(85,85,85), ColorLib.rgb(0,0,0)), 0, 9);

        public FillColorAction(String group) {
            super(group, VisualItem.FILLCOLOR);
        }
        
        public int getColor(VisualItem item) {
            if ( item instanceof NodeItem ) {
                NodeItem nitem = (NodeItem)item;
                if ( nitem.getChildCount() > 0 ) {
                    return 0; // no fill for parent nodes
                } else {
                    if ( m_vis.isInGroup(item, Visualization.SEARCH_ITEMS) )
                        return ColorLib.rgb(150,150,0);
                    else
                        return cmap.getColor(nitem.getDepth());
                }
            } else {
                return cmap.getColor(0);
            }
        }
        
    }
    
    public static class LabelLayout extends Layout {
        public LabelLayout(String group) {
            super(group);
        }
        public void run(double frac) {
            Iterator iter = m_vis.items(m_group);
            while ( iter.hasNext() ) {
                DecoratorItem item = (DecoratorItem)iter.next();
                VisualItem node = item.getDecoratedItem();
                Rectangle2D bounds = node.getBounds();
                setX(item, null, bounds.getCenterX());
                setY(item, null, bounds.getCenterY());
            }
        }
    }
    
    public static class NodeRenderer extends AbstractShapeRenderer {
        private Rectangle2D m_bounds = new Rectangle2D.Double();
        
        public NodeRenderer() {
            m_manageBounds = false;
        }
        protected Shape getRawShape(VisualItem item) {
            m_bounds.setRect(item.getBounds());
            return m_bounds;
        }
    }
    
}
